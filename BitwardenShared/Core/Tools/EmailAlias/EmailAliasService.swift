import BitwardenSdk
import Foundation

// The actor owns the complete lifecycle so cancellation and decrypted-state clearing stay serialized.
// swiftlint:disable file_length

struct EmailAliasProfile: Equatable, Sendable {
    let token: String
    let baseUrl: String
    let connectionId: String
    let cachedAlias: EmailAliasResult?
}

protocol EmailAliasService: AnyObject {
    /// Loads encrypted local state only. This method must never contact the alias provider.
    func loadProfile(baseUrl: String) async throws -> EmailAliasProfile?

    /// Creates an alias after the caller receives an explicit user action.
    func createAlias(token: String, baseUrl: String, hostname: String?) async throws -> EmailAliasResult

    /// Changes forwarding state after an explicit user action.
    func setAliasEnabled(_ alias: EmailAliasResult, enabled: Bool) async throws -> EmailAliasResult

    /// Deletes an alias after an explicit user action.
    func deleteAlias(_ alias: EmailAliasResult) async throws -> EmailAliasResult

    /// Performs an explicit provider/vault reconciliation.
    func reconcile(baseUrl: String) async throws -> EmailAliasResult?

    /// Cancels in-flight provider work and clears all decrypted carrier state.
    func cancelAndClear() async
}

actor DefaultEmailAliasService: EmailAliasService { // swiftlint:disable:this type_body_length
    typealias ClientFactory = @Sendable (AliasClientSettings) throws -> any AliasClientProtocol

    private struct Context: Sendable {
        let userId: String
        let generation: UInt64
    }

    private struct ConnectionState: Sendable {
        let connection: AliasProviderConnection
        let credential: AliasConnectionCredential
        var sync: AliasSyncDocument
    }

    private struct JournalIndex {
        var deleted = Set<EmailAliasIdentity>()
        var dispatchedOperationIds = Set<String>()
        var operations = [String: AliasProviderOperation]()
        var snapshots = [AliasProviderSnapshot]()
        var terminalOperationIds = Set<String>()
        var unknownOperationIds = Set<String>()
    }

    private let cipherService: CipherService
    private let clientFactory: ClientFactory
    private let clientService: ClientService
    private let replicaId = UUID().uuidString.lowercased()
    private let stateService: StateService
    private let syncService: SyncService
    private let vaultTimeoutService: VaultTimeoutService

    private var activeOperation: Task<EmailAliasResult?, Error>?
    private var decryptedPayloads = [AliasConnectionVaultPayload]()
    private var generation: UInt64 = 0

    init(
        cipherService: CipherService,
        clientService: ClientService,
        stateService: StateService,
        syncService: SyncService,
        vaultTimeoutService: VaultTimeoutService,
        clientFactory: @escaping ClientFactory = { try AliasClient(settings: $0) },
    ) {
        self.cipherService = cipherService
        self.clientService = clientService
        self.stateService = stateService
        self.syncService = syncService
        self.vaultTimeoutService = vaultTimeoutService
        self.clientFactory = clientFactory
    }

    func loadProfile(baseUrl: String) async throws -> EmailAliasProfile? {
        let context = try await context()
        defer { clearDecryptedState() }
        let canonicalBaseUrl = try canonicalBaseUrl(baseUrl)
        guard let state = try await loadConnection(baseUrl: canonicalBaseUrl, context: context) else {
            return nil
        }
        let cachedAlias = try cachedAlias(in: state.sync, connection: state.connection, excluding: [])
        return EmailAliasProfile(
            token: state.credential.token,
            baseUrl: state.credential.baseUrl,
            connectionId: state.connection.connectionId,
            cachedAlias: cachedAlias,
        )
    }

    func createAlias(token: String, baseUrl: String, hostname: String?) async throws -> EmailAliasResult {
        guard let result = try await runOperation({
            try await self.performCreate(token: token, baseUrl: baseUrl, hostname: hostname)
        }) else { throw EmailAliasError.invalidEncryptedState }
        return result
    }

    func setAliasEnabled(_ alias: EmailAliasResult, enabled: Bool) async throws -> EmailAliasResult {
        guard let result = try await runOperation({
            try await self.performSetEnabled(alias, enabled: enabled)
        }) else { throw EmailAliasError.invalidEncryptedState }
        return result
    }

    func deleteAlias(_ alias: EmailAliasResult) async throws -> EmailAliasResult {
        guard let result = try await runOperation({
            try await self.performDelete(alias)
        }) else { throw EmailAliasError.invalidEncryptedState }
        return result
    }

    func reconcile(baseUrl: String) async throws -> EmailAliasResult? {
        try await runOperation {
            try await self.performReconciliation(baseUrl: baseUrl)
        }
    }

    func cancelAndClear() {
        generation &+= 1
        activeOperation?.cancel()
        activeOperation = nil
        clearDecryptedState()
    }

    // MARK: - Explicit operations

    private func runOperation(
        _ operation: @escaping @Sendable () async throws -> EmailAliasResult?,
    ) async throws -> EmailAliasResult? {
        activeOperation?.cancel()
        generation &+= 1
        let operationGeneration = generation
        let task = Task { try await operation() }
        activeOperation = task
        defer {
            if generation == operationGeneration {
                activeOperation = nil
                clearDecryptedState()
            }
        }
        return try await task.value
    }

    // swiftlint:disable:next function_body_length
    private func performCreate(token: String, baseUrl: String, hostname: String?) async throws -> EmailAliasResult {
        let context = try await context()
        let canonicalBaseUrl = try canonicalBaseUrl(baseUrl)
        let credential = AliasConnectionCredential(token: token, baseUrl: canonicalBaseUrl)
        var connection = try await loadConnection(baseUrl: canonicalBaseUrl, context: context)
        if let connection, connection.credential != credential {
            throw EmailAliasError.conflict
        }
        if connection == nil {
            connection = try await createConnection(credential: credential, context: context)
        }
        guard var connection else { throw EmailAliasError.invalidEncryptedState }

        let operation = AliasProviderOperation(
            operation: "create",
            connection: connection.connection,
            request: AliasCreateIntent(kind: "random", hostname: hostname, mode: nil, note: nil),
            alias: nil,
        )
        let operationEvent: AliasSyncEvent
        do {
            operationEvent = try await appendAndPersist(
                kind: "provider-operation",
                value: operation,
                state: &connection,
                context: context,
            )
            _ = try await appendAndPersist(
                kind: "provider-dispatched",
                operationId: operationEvent.id,
                state: &connection,
                context: context,
            )
        } catch {
            // A provider call is never made unless its encrypted dispatch marker was persisted.
            // Offline use is limited to an already observed, unbound alias and never queues creation.
            let used = await (try? boundAliases(context: context)) ?? []
            if let cached = try cachedAlias(in: connection.sync, connection: connection.connection, excluding: used) {
                return cached
            }
            throw error
        }
        try await validate(context)

        let client = try makeClient(connection)
        do {
            let alias = try await client.createRandomAlias(request: CreateRandomAliasRequest(
                hostname: hostname,
                mode: nil,
                note: nil,
            ))
            try await validate(context)
            let reference = try client.createAliasReference(alias: alias)
            var result = EmailAliasResult(
                address: alias.email,
                reference: reference,
                identity: EmailAliasIdentity(alias: alias, connection: connection.connection),
                status: alias.enabled ? .enabled : .disabled,
            )
            do {
                _ = try await appendAndPersist(
                    kind: "provider-ack",
                    operationId: operationEvent.id,
                    snapshot: AliasProviderSnapshot(alias: alias, connection: connection.connection),
                    state: &connection,
                    context: context,
                )
            } catch {
                // The provider result remains valid even when its encrypted journal acknowledgement
                // cannot be saved. The login can still be saved with the canonical SDK reference.
                result.journalPersistenceFailed = true
            }
            return result
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as AliasError {
            return try await handleCreateFailure(
                error,
                operationId: operationEvent.id,
                state: &connection,
                context: context,
            )
        }
    }

    // swiftlint:disable:next function_body_length
    private func performSetEnabled(
        _ result: EmailAliasResult,
        enabled: Bool,
    ) async throws -> EmailAliasResult {
        let context = try await context()
        var connection = try await requiredConnection(for: result.identity, context: context)
        let operationName = enabled ? "enable" : "disable"
        let operation = AliasProviderOperation(
            operation: operationName,
            connection: nil,
            request: nil,
            alias: result.identity,
        )
        let operationEvent = try await appendAndPersist(
            kind: "provider-operation",
            value: operation,
            state: &connection,
            context: context,
        )
        _ = try await appendAndPersist(
            kind: "provider-dispatched",
            operationId: operationEvent.id,
            state: &connection,
            context: context,
        )
        let client = try makeClient(connection)
        do {
            let providerState = try await client.setAliasEnabled(
                aliasId: aliasId(result.identity),
                enabled: enabled,
            )
            try await validate(context)
            var updated = result
            updated.status = providerState.enabled ? .enabled : .disabled
            let snapshot = AliasProviderSnapshot(
                alias: result.identity,
                enabled: providerState.enabled,
            )
            do {
                _ = try await appendAndPersist(
                    kind: "provider-ack",
                    operationId: operationEvent.id,
                    snapshot: snapshot,
                    state: &connection,
                    context: context,
                )
            } catch {
                updated.journalPersistenceFailed = true
            }
            return updated
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as AliasError {
            try await recordMutationFailure(error, operationId: operationEvent.id, state: &connection, context: context)
            throw map(error)
        }
    }

    private func performDelete(_ result: EmailAliasResult) async throws -> EmailAliasResult {
        let context = try await context()
        var connection = try await requiredConnection(for: result.identity, context: context)
        let operation = AliasProviderOperation(
            operation: "delete",
            connection: nil,
            request: nil,
            alias: result.identity,
        )
        let operationEvent = try await appendAndPersist(
            kind: "provider-operation",
            value: operation,
            state: &connection,
            context: context,
        )
        _ = try await appendAndPersist(
            kind: "provider-dispatched",
            operationId: operationEvent.id,
            state: &connection,
            context: context,
        )
        let client = try makeClient(connection)
        do {
            let deletion = try await client.deleteAlias(aliasId: aliasId(result.identity))
            try await validate(context)
            guard deletion.deleted else { throw EmailAliasError.providerRejected }
            var deleted = result
            deleted.status = .deleted
            do {
                _ = try await appendAndPersist(
                    kind: "provider-ack",
                    operationId: operationEvent.id,
                    state: &connection,
                    context: context,
                )
            } catch {
                deleted.journalPersistenceFailed = true
            }
            return deleted
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as AliasError {
            try await recordMutationFailure(error, operationId: operationEvent.id, state: &connection, context: context)
            throw map(error)
        }
    }

    private func performReconciliation(baseUrl: String) async throws -> EmailAliasResult? {
        let context = try await context()
        try await syncService.fetchSync(forceSync: true, isPeriodic: false)
        try await validate(context)
        let canonicalBaseUrl = try canonicalBaseUrl(baseUrl)
        guard var connection = try await loadConnection(baseUrl: canonicalBaseUrl, context: context) else {
            return nil
        }
        let client = try makeClient(connection)
        var aliases = [BitwardenSdk.Alias]()
        for pageNumber in 0 ..< 100 {
            let page = try await client.listAliases(page: UInt32(pageNumber), filter: nil)
            try await validate(context)
            if page.aliases.isEmpty { break }
            aliases.append(contentsOf: page.aliases)
        }

        for alias in aliases {
            _ = try await appendAndPersist(
                kind: "provider-observe",
                snapshot: AliasProviderSnapshot(alias: alias, connection: connection.connection),
                state: &connection,
                context: context,
            )
        }
        try await reconcileLoginBindings(aliases: aliases, connection: connection, context: context)
        return try cachedAlias(in: connection.sync, connection: connection.connection, excluding: [])
    }

    // MARK: - Carrier persistence

    private func createConnection(
        credential: AliasConnectionCredential,
        context: Context,
    ) async throws -> ConnectionState {
        let providerInstance = try canonicalBaseUrl(credential.baseUrl)
        let connection = AliasProviderConnection(
            providerInstance: providerInstance,
            connectionId: UUID().uuidString.lowercased(),
        )
        var sync = AliasSyncDocument(replicaId: replicaId)
        let event = try sync.append(kind: "connection-upsert", connection: connection)
        let state = ConnectionState(connection: connection, credential: credential, sync: sync)
        try await persist(event: event, state: state, credential: credential, context: context)
        return state
    }

    private func appendAndPersist(
        kind: String,
        value: AliasProviderOperation? = nil,
        operationId: String? = nil,
        snapshot: AliasProviderSnapshot? = nil,
        reason: String? = nil,
        state: inout ConnectionState,
        context: Context,
    ) async throws -> AliasSyncEvent {
        let event = try state.sync.append(
            kind: kind,
            value: value,
            operationId: operationId,
            snapshot: snapshot,
            reason: reason,
        )
        try await persist(event: event, state: state, credential: nil, context: context)
        return event
    }

    private func persist(
        event: AliasSyncEvent,
        state: ConnectionState,
        credential: AliasConnectionCredential?,
        context: Context,
    ) async throws {
        try await validate(context)
        let segment = AliasSyncDocument(
            version: AliasConnectionSchema.version,
            replicaId: state.sync.replicaId,
            clock: state.sync.clock,
            events: [event],
        )
        let payload = AliasConnectionVaultPayload(
            version: AliasConnectionSchema.version,
            connection: state.connection,
            credential: credential,
            sync: segment,
        )
        let view = try AliasConnectionVaultCodec.encode(payload)
        let encrypted = try await clientService.vault().ciphers().encrypt(cipherView: view)
        try await validate(context)
        do {
            try await cipherService.addCipherWithServer(encrypted.cipher, encryptedFor: encrypted.encryptedFor)
        } catch {
            try? await syncService.fetchSync(forceSync: true, isPeriodic: false)
            let records = try? await loadPayloads(context: context)
            if records?.contains(where: { payload in
                payload.sync.events.contains(where: { record in record.id == event.id })
            }) == true {
                return
            }
            throw EmailAliasError.conflict
        }
        try await validate(context)
    }

    private func loadConnection(baseUrl: String, context: Context) async throws -> ConnectionState? {
        let payloads = try await loadPayloads(context: context).filter { payload in
            payload.connection.providerInstance == baseUrl
        }
        guard !payloads.isEmpty else { return nil }
        let connectionIds = Set(payloads.map(\.connection.connectionId))
        guard connectionIds.count == 1, let connection = payloads.first?.connection else {
            throw EmailAliasError.conflict
        }
        let credentials = Set(payloads.compactMap(\.credential))
        guard credentials.count == 1, let credential = credentials.first else {
            throw EmailAliasError.conflict
        }
        let merged = try AliasSyncDocument.merged(payloads.map(\.sync), replicaId: replicaId)
        if merged.events.contains(where: { event in
            event.kind == "connection-remove" && event.connection == connection
        }) {
            return nil
        }
        return ConnectionState(connection: connection, credential: credential, sync: merged)
    }

    private func requiredConnection(
        for identity: EmailAliasIdentity,
        context: Context,
    ) async throws -> ConnectionState {
        guard let connection = try await loadConnection(baseUrl: identity.providerInstance, context: context),
              connection.connection.connectionId == identity.connectionId
        else { throw EmailAliasError.conflict }
        return connection
    }

    private func loadPayloads(context: Context) async throws -> [AliasConnectionVaultPayload] {
        try await validate(context)
        let ciphers = try await cipherService.fetchAllCiphers()
        var payloads = [AliasConnectionVaultPayload]()
        for cipher in ciphers {
            try await validate(context)
            guard cipher.type == .secureNote else { continue }
            let view = try await clientService.vault().ciphers().decrypt(cipher: cipher)
            if view.isAliasConnectionCarrier {
                try payloads.append(AliasConnectionVaultCodec.decode(view))
            }
        }
        decryptedPayloads = payloads
        return payloads
    }

    // MARK: - Reconciliation and cached reuse

    private func reconcileLoginBindings(
        aliases: [BitwardenSdk.Alias],
        connection: ConnectionState,
        context: Context,
    ) async throws {
        let encryptedCiphers = try await cipherService.fetchAllCiphers().filter { $0.type == .login }
        let ciphers = try await encryptedCiphers.asyncMap { cipher in
            try await clientService.vault().ciphers().decrypt(cipher: cipher)
        }
        let provider = try makeClient(connection).providerIdentity()
        let plan = try planAliasReconciliation(provider: provider, aliases: aliases, ciphers: ciphers)
        guard !plan.actions.isEmpty else { return }
        let output = try applyAliasReconciliation(plan: plan, aliases: aliases, ciphers: ciphers)
        let changedIds = Set(output.result.changedCipherIds)
        for cipher in output.ciphers where cipher.id.map(changedIds.contains) == true {
            try await validate(context)
            let encrypted = try await clientService.vault().ciphers().encrypt(cipherView: cipher)
            try await cipherService.updateCipherWithServer(
                encrypted.cipher,
                encryptedFor: encrypted.encryptedFor,
            )
        }
    }

    private func cachedAlias(
        in document: AliasSyncDocument,
        connection: AliasProviderConnection,
        excluding usedAliases: Set<EmailAliasIdentity>,
    ) throws -> EmailAliasResult? {
        var index = journalIndex(document)
        index.unknownOperationIds.formUnion(
            index.dispatchedOperationIds.subtracting(index.terminalOperationIds),
        )
        let hasUnknownCreate = index.unknownOperationIds.contains(where: { operationId in
            index.operations[operationId]?.operation == "create"
        })
        guard let snapshot = index.snapshots.reversed().first(where: { snapshot in
            snapshot.enabled
                && !index.deleted.contains(snapshot.alias)
                && !usedAliases.contains(snapshot.alias)
        }), let reference = snapshot.alias.sdkReference else {
            if hasUnknownCreate { throw EmailAliasError.operationOutcomeUnknown }
            return nil
        }
        return try EmailAliasResult(
            address: snapshot.alias.address,
            reference: serializeAliasReference(reference: reference),
            identity: snapshot.alias,
            status: hasUnknownCreate ? .unknown : .enabled,
        )
    }

    private func journalIndex(_ document: AliasSyncDocument) -> JournalIndex {
        var index = JournalIndex()
        for event in document.events {
            switch event.kind {
            case "provider-operation":
                if let value = event.value {
                    index.operations[event.id] = value
                }
            case "provider-dispatched":
                if let operationId = event.operationId {
                    index.dispatchedOperationIds.insert(operationId)
                }
            case "provider-ack":
                if let operationId = event.operationId {
                    index.terminalOperationIds.insert(operationId)
                    if index.operations[operationId]?.operation == "delete",
                       let identity = index.operations[operationId]?.alias {
                        index.deleted.insert(identity)
                    }
                }
                if let snapshot = event.snapshot {
                    index.snapshots.append(snapshot)
                }
            case "provider-observe":
                if let snapshot = event.snapshot {
                    index.snapshots.append(snapshot)
                }
            case "provider-unknown":
                if let operationId = event.operationId {
                    index.terminalOperationIds.insert(operationId)
                    index.unknownOperationIds.insert(operationId)
                }
            case "provider-failed":
                if let operationId = event.operationId {
                    index.terminalOperationIds.insert(operationId)
                }
            default:
                break
            }
        }
        return index
    }

    private func handleCreateFailure(
        _ error: AliasError,
        operationId: String,
        state: inout ConnectionState,
        context: Context,
    ) async throws -> EmailAliasResult {
        let isUnknown = switch error {
        case .MutationCommittedButRefreshFailed,
             .MutationOutcomeUnknown,
             .MutationResponseInvalid,
             .Transport:
            true
        default:
            false
        }
        if isUnknown {
            try? await appendAndPersist(
                kind: "provider-unknown",
                operationId: operationId,
                state: &state,
                context: context,
            )
            let used = try await boundAliases(context: context)
            if var cached = try cachedAlias(in: state.sync, connection: state.connection, excluding: used) {
                cached.status = .unknown
                return cached
            }
            throw EmailAliasError.operationOutcomeUnknown
        }
        try? await appendAndPersist(
            kind: "provider-failed",
            operationId: operationId,
            reason: failureReason(error),
            state: &state,
            context: context,
        )
        throw map(error)
    }

    private func recordMutationFailure(
        _ error: AliasError,
        operationId: String,
        state: inout ConnectionState,
        context: Context,
    ) async throws {
        let isUnknown = switch error {
        case .MutationCommittedButRefreshFailed,
             .MutationOutcomeUnknown,
             .MutationResponseInvalid,
             .Transport:
            true
        default:
            false
        }
        _ = try? await appendAndPersist(
            kind: isUnknown ? "provider-unknown" : "provider-failed",
            operationId: operationId,
            reason: isUnknown ? nil : failureReason(error),
            state: &state,
            context: context,
        )
    }

    private func boundAliases(context: Context) async throws -> Set<EmailAliasIdentity> {
        let encrypted = try await cipherService.fetchAllCiphers().filter { $0.type == .login }
        var identities = Set<EmailAliasIdentity>()
        for cipher in encrypted {
            try await validate(context)
            let view = try await clientService.vault().ciphers().decrypt(cipher: cipher)
            guard let value = view.login?.aliasReference,
                  let reference = try? parseAliasReference(value: value)
            else { continue }
            identities.insert(EmailAliasIdentity(
                version: Int(reference.version),
                provider: "simplelogin",
                providerInstance: reference.providerInstance,
                connectionId: reference.connectionId,
                aliasId: String(reference.aliasId),
                address: reference.address,
            ))
        }
        return identities
    }

    // MARK: - Safety helpers

    private func context() async throws -> Context {
        let userId = try await stateService.getActiveAccountId()
        guard await !vaultTimeoutService.isLocked(userId: userId) else { throw EmailAliasError.locked }
        return Context(userId: userId, generation: generation)
    }

    private func validate(_ context: Context) async throws {
        try Task.checkCancellation()
        guard generation == context.generation else { throw CancellationError() }
        guard await (try? stateService.getActiveAccountId()) == context.userId else {
            throw EmailAliasError.accountChanged
        }
        guard await !vaultTimeoutService.isLocked(userId: context.userId) else {
            throw EmailAliasError.locked
        }
    }

    private func canonicalBaseUrl(_ value: String) throws -> String {
        let candidate = value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? ForwardedEmailServiceType.defaultSimpleLoginBaseUrl
            : value
        guard let canonical = AliasSyncValidation.canonicalProviderInstance(candidate) else {
            throw EmailAliasError.invalidConfiguration
        }
        return canonical
    }

    private func makeClient(_ state: ConnectionState) throws -> any AliasClientProtocol {
        try clientFactory(AliasClientSettings(
            baseUrl: state.credential.baseUrl,
            apiToken: state.credential.token,
            connectionId: state.connection.connectionId,
        ))
    }

    private func aliasId(_ identity: EmailAliasIdentity) throws -> UInt64 {
        guard let id = UInt64(identity.aliasId) else { throw EmailAliasError.invalidEncryptedState }
        return id
    }

    private func map(_ error: AliasError) -> EmailAliasError {
        switch error {
        case .MutationCommittedButRefreshFailed,
             .MutationOutcomeUnknown,
             .MutationResponseInvalid,
             .Transport:
            .operationOutcomeUnknown
        case .InvalidAuthenticationToken,
             .InvalidBaseUrl,
             .InvalidConnectionIdentity,
             .InvalidRequest:
            .invalidConfiguration
        default:
            .providerRejected
        }
    }

    private func failureReason(_ error: AliasError) -> String {
        switch error {
        case .AuthenticationFailed: "invalid-credentials"
        case .RateLimited: "rate-limited"
        case .Provider: "forbidden"
        default: "invalid-response"
        }
    }

    private func clearDecryptedState() {
        decryptedPayloads.removeAll(keepingCapacity: false)
    }
}

private extension AliasProviderSnapshot {
    init(alias: EmailAliasIdentity, enabled: Bool) {
        self.alias = alias
        self.enabled = enabled
        name = nil
        note = nil
        mailboxIds = nil
        pgpDisabled = nil
        pinned = nil
    }
}

private extension AliasSyncDocument {
    init(version: Int, replicaId: String, clock: [String: Int], events: [AliasSyncEvent]) {
        self.version = version
        self.replicaId = replicaId
        self.clock = clock
        self.events = events
    }
}

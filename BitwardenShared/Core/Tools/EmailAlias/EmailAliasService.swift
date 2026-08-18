import BitwardenSdk
import Foundation

// The actor owns connection state and operation lifetime. The SDK owns the canonical contract,
// pure journal reduction, reference codec, and reconciliation algorithms.
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

/// Composition-root registration for a provider implementation. The service depends only on this
/// neutral descriptor and never branches on provider names or native payloads.
struct AliasAdapterRegistration: Sendable {
    let adapterId: String
    let defaultBaseUrl: String
    let makeConnection: @Sendable (_ connectionId: String) -> AliasConnection
    let makeClient: @Sendable (
        _ connection: AliasConnection,
        _ credential: AliasConnectionCredential,
    ) throws -> any AliasClientProtocol
}

actor DefaultEmailAliasService: EmailAliasService { // swiftlint:disable:this type_body_length
    private struct Context: Sendable {
        let userId: String
        let generation: UInt64
    }

    private struct ConnectionState: Sendable {
        let connection: AliasConnection
        let credential: AliasConnectionCredential
        var journal: AliasJournal
    }

    private struct FailureRecord: Sendable {
        let error: AliasError
        let lifecycle: AliasLifecycleState?
        let operation: AliasOperationKind
        let operationId: String
        let target: AliasIdentity?

        init(
            error: AliasError,
            operationId: String,
            operation: AliasOperationKind,
            target: AliasIdentity?,
            lifecycle: AliasLifecycleState? = nil,
        ) {
            self.error = error
            self.lifecycle = lifecycle
            self.operation = operation
            self.operationId = operationId
            self.target = target
        }
    }

    private let adapter: AliasAdapterRegistration
    private let cipherService: CipherService
    private let clientService: ClientService
    private let replicaId = UUID().uuidString.lowercased()
    private let stateService: StateService
    private let syncService: SyncService
    private let vaultTimeoutService: VaultTimeoutService

    private var cancelActiveOperation: (@Sendable () -> Void)?
    private var decryptedPayloads = [AliasConnectionVaultPayload]()
    private var generation: UInt64 = 0

    init(
        adapter: AliasAdapterRegistration,
        cipherService: CipherService,
        clientService: ClientService,
        stateService: StateService,
        syncService: SyncService,
        vaultTimeoutService: VaultTimeoutService,
    ) {
        self.adapter = adapter
        self.cipherService = cipherService
        self.clientService = clientService
        self.stateService = stateService
        self.syncService = syncService
        self.vaultTimeoutService = vaultTimeoutService
    }

    func loadProfile(baseUrl: String) async throws -> EmailAliasProfile? {
        let context = try await context()
        defer { clearDecryptedState() }
        let endpoint = try canonicalBaseUrl(baseUrl)
        guard let state = try await loadConnection(baseUrl: endpoint, context: context) else { return nil }
        let used = try await boundAliases(context: context)
        return try EmailAliasProfile(
            token: state.credential.token,
            baseUrl: state.credential.baseUrl,
            connectionId: state.connection.connectionId,
            cachedAlias: cachedAlias(in: state.journal, excluding: used),
        )
    }

    func createAlias(token: String, baseUrl: String, hostname: String?) async throws -> EmailAliasResult {
        try await runOperation {
            try await self.performCreate(token: token, baseUrl: baseUrl, hostname: hostname)
        }
    }

    func setAliasEnabled(_ alias: EmailAliasResult, enabled: Bool) async throws -> EmailAliasResult {
        try await runOperation { try await self.performSetEnabled(alias, enabled: enabled) }
    }

    func deleteAlias(_ alias: EmailAliasResult) async throws -> EmailAliasResult {
        try await runOperation { try await self.performDelete(alias) }
    }

    func reconcile(baseUrl: String) async throws -> EmailAliasResult? {
        try await runOperation { try await self.performReconciliation(baseUrl: baseUrl) }
    }

    func cancelAndClear() {
        generation &+= 1
        cancelActiveOperation?()
        cancelActiveOperation = nil
        clearDecryptedState()
    }

    // MARK: - Explicit operations

    private func runOperation<Result: Sendable>(
        _ operation: @escaping @Sendable () async throws -> Result,
    ) async throws -> Result {
        cancelActiveOperation?()
        generation &+= 1
        let operationGeneration = generation
        let task = Task<Result, Error> { try await operation() }
        cancelActiveOperation = { task.cancel() }
        defer {
            if generation == operationGeneration {
                cancelActiveOperation = nil
                clearDecryptedState()
            }
        }
        return try await task.value
    }

    // swiftlint:disable:next function_body_length
    private func performCreate(token: String, baseUrl: String, hostname: String?) async throws -> EmailAliasResult {
        let context = try await context()
        let endpoint = try canonicalBaseUrl(baseUrl)
        let credential = AliasConnectionCredential(token: token, baseUrl: endpoint)
        var loaded = try await loadConnection(baseUrl: endpoint, context: context)
        if let loaded, loaded.credential != credential { throw EmailAliasError.conflict }
        if loaded == nil { loaded = try await createConnection(credential: credential, context: context) }
        guard var state = loaded else { throw EmailAliasError.invalidEncryptedState }
        try rejectUncertainCreate(in: state.journal)

        let originalJournal = state.journal
        let operationId = UUID().uuidString.lowercased()
        do {
            try await appendAndPersist(
                operationId: operationId,
                operation: .create,
                phase: .prepared,
                state: &state,
                context: context,
            )
            try await appendAndPersist(
                operationId: operationId,
                operation: .create,
                phase: .dispatched,
                state: &state,
                context: context,
            )
        } catch {
            // No callback occurs unless the encrypted dispatch fact is durable. A failed journal
            // write may reuse only a previously observed and currently unbound resource.
            state.journal = originalJournal
            let used = await (try? boundAliases(context: context)) ?? []
            if let cached = try cachedAlias(in: state.journal, excluding: used) { return cached }
            throw error
        }

        let client = try makeClient(state)
        do {
            let alias = try await client.create(request: CreateAliasRequest(hostname: normalizedHostname(hostname)))
            try await validate(context)
            var result = try result(alias)
            do {
                try await appendAndPersist(
                    operationId: operationId,
                    operation: .create,
                    phase: .acknowledged,
                    target: alias.identity,
                    lifecycle: alias.lifecycle,
                    state: &state,
                    context: context,
                )
            } catch {
                // The provider result is still usable; the login retains the canonical reference
                // and later reconciliation can recover the missing acknowledgement.
                result.journalPersistenceFailed = true
            }
            return result
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as AliasError {
            try await validate(context)
            return try await handleCreateFailure(
                error,
                operationId: operationId,
                state: &state,
                context: context,
            )
        } catch {
            try await validate(context)
            try? await recordFailure(FailureRecord(
                error: .LocalSecurityFailure,
                operationId: operationId,
                operation: .create,
                target: nil,
            ),
            state: &state,
            context: context)
            throw EmailAliasError.providerRejected
        }
    }

    private func performSetEnabled(_ result: EmailAliasResult, enabled: Bool) async throws -> EmailAliasResult {
        let context = try await context()
        var state = try await requiredConnection(for: result.identity, context: context)
        let operation: AliasOperationKind = enabled ? .enable : .disable
        let lifecycle: AliasLifecycleState = enabled ? .enabled : .disabled
        let operationId = UUID().uuidString.lowercased()
        try await prepareAndDispatch(
            operationId: operationId,
            operation: operation,
            target: result.identity,
            lifecycle: lifecycle,
            state: &state,
            context: context,
        )
        let client = try makeClient(state)
        do {
            let alias = try await client.setEnabled(identity: result.identity, enabled: enabled)
            try await validate(context)
            var updated = try self.result(alias)
            do {
                try await appendAndPersist(
                    operationId: operationId,
                    operation: operation,
                    phase: .acknowledged,
                    target: alias.identity,
                    lifecycle: alias.lifecycle,
                    state: &state,
                    context: context,
                )
            } catch {
                updated.journalPersistenceFailed = true
            }
            return updated
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as AliasError {
            try await validate(context)
            try? await recordFailure(FailureRecord(
                error: error,
                operationId: operationId,
                operation: operation,
                target: result.identity,
                lifecycle: lifecycle,
            ),
            state: &state,
            context: context)
            throw map(error)
        }
    }

    private func performDelete(_ result: EmailAliasResult) async throws -> EmailAliasResult {
        let context = try await context()
        var state = try await requiredConnection(for: result.identity, context: context)
        let operationId = UUID().uuidString.lowercased()
        try await prepareAndDispatch(
            operationId: operationId,
            operation: .delete,
            target: result.identity,
            lifecycle: .deleted,
            state: &state,
            context: context,
        )
        let client = try makeClient(state)
        do {
            let deletion = try await client.delete(identity: result.identity)
            try await validate(context)
            guard deletion.deleted, deletion.identity == result.identity else {
                throw AliasError.InvalidResponse
            }
            var deleted = result
            deleted.status = .deleted
            do {
                try await appendAndPersist(
                    operationId: operationId,
                    operation: .delete,
                    phase: .acknowledged,
                    target: result.identity,
                    lifecycle: .deleted,
                    state: &state,
                    context: context,
                )
            } catch {
                deleted.journalPersistenceFailed = true
            }
            return deleted
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as AliasError {
            try await validate(context)
            try? await recordFailure(FailureRecord(
                error: error,
                operationId: operationId,
                operation: .delete,
                target: result.identity,
                lifecycle: .deleted,
            ),
            state: &state,
            context: context)
            throw map(error)
        }
    }

    // swiftlint:disable:next function_body_length
    private func performReconciliation(baseUrl: String) async throws -> EmailAliasResult? {
        let context = try await context()
        try await syncService.fetchSync(forceSync: true, isPeriodic: false)
        try await validate(context)
        let endpoint = try canonicalBaseUrl(baseUrl)
        guard var state = try await loadConnection(baseUrl: endpoint, context: context) else { return nil }

        let operationId = UUID().uuidString.lowercased()
        try await prepareAndDispatch(
            operationId: operationId,
            operation: .reconcile,
            state: &state,
            context: context,
        )
        let client = try makeClient(state)
        do {
            var aliases = [BitwardenSdk.Alias]()
            var pageToken: String?
            var observedTokens = Set<String>()
            for _ in 0 ..< 100 {
                let page = try await client.list(request: ListAliasesRequest(pageToken: pageToken))
                try await validate(context)
                aliases.append(contentsOf: page.aliases)
                guard let next = page.nextPageToken else { break }
                guard observedTokens.insert(next).inserted else { throw AliasError.InvalidResponse }
                pageToken = next
            }
            if pageToken != nil, observedTokens.count == 100 { throw AliasError.InvalidResponse }
            guard Set(aliases.map(\.identity)).count == aliases.count else { throw AliasError.InvalidResponse }

            for alias in aliases {
                try await appendAndPersist(
                    operationId: UUID().uuidString.lowercased(),
                    operation: .get,
                    phase: .acknowledged,
                    target: alias.identity,
                    lifecycle: alias.lifecycle,
                    state: &state,
                    context: context,
                )
            }
            try await reconcileLoginBindings(aliases: aliases, state: state, context: context)
            try await appendAndPersist(
                operationId: operationId,
                operation: .reconcile,
                phase: .acknowledged,
                state: &state,
                context: context,
            )
            let used = try await boundAliases(context: context)
            return try cachedAlias(in: state.journal, excluding: used)
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as AliasError {
            try await validate(context)
            try? await recordFailure(FailureRecord(
                error: error,
                operationId: operationId,
                operation: .reconcile,
                target: nil,
            ),
            state: &state,
            context: context)
            throw map(error)
        }
    }

    // MARK: - Canonical journal persistence

    private func createConnection(
        credential: AliasConnectionCredential,
        context: Context,
    ) async throws -> ConnectionState {
        let connection = adapter.makeConnection(UUID().uuidString.lowercased())
        let journal = try AliasJournal.empty(connectionId: connection.connectionId)
        let state = ConnectionState(connection: connection, credential: credential, journal: journal)
        try await persist(state: state, credential: credential, expectedEventId: nil, context: context)
        return state
    }

    private func prepareAndDispatch(
        operationId: String,
        operation: AliasOperationKind,
        target: AliasIdentity? = nil,
        lifecycle: AliasLifecycleState? = nil,
        state: inout ConnectionState,
        context: Context,
    ) async throws {
        try await appendAndPersist(
            operationId: operationId,
            operation: operation,
            phase: .prepared,
            target: target,
            lifecycle: lifecycle,
            state: &state,
            context: context,
        )
        try await appendAndPersist(
            operationId: operationId,
            operation: operation,
            phase: .dispatched,
            target: target,
            lifecycle: lifecycle,
            state: &state,
            context: context,
        )
    }

    private func appendAndPersist(
        operationId: String,
        operation: AliasOperationKind,
        phase: AliasOperationPhase,
        target: AliasIdentity? = nil,
        lifecycle: AliasLifecycleState? = nil,
        error: AliasErrorCode? = nil,
        state: inout ConnectionState,
        context: Context,
    ) async throws {
        let event = try state.journal.append(
            replicaId: replicaId,
            operationId: operationId,
            operation: operation,
            phase: phase,
            target: target,
            lifecycle: lifecycle,
            error: error,
        )
        try await persist(state: state, credential: nil, expectedEventId: event.eventId, context: context)
    }

    private func persist(
        state: ConnectionState,
        credential: AliasConnectionCredential?,
        expectedEventId: String?,
        context: Context,
    ) async throws {
        try await validate(context)
        let payload = AliasConnectionVaultPayload(
            version: AliasConnectionSchema.version,
            connection: state.connection,
            credential: credential,
            journal: state.journal,
        )
        let view = try AliasConnectionVaultCodec.encode(payload)
        let encrypted = try await clientService.vault().ciphers().encrypt(cipherView: view)
        try await validate(context)
        do {
            try await cipherService.addCipherWithServer(encrypted.cipher, encryptedFor: encrypted.encryptedFor)
        } catch {
            try? await syncService.fetchSync(forceSync: true, isPeriodic: false)
            if let expectedEventId,
               let payloads = try? await loadPayloads(context: context),
               payloads.contains(where: { payload in
                   payload.connection.connectionId == state.connection.connectionId
                       && payload.journal.events.contains(where: { $0.eventId == expectedEventId })
               }) {
                return
            }
            throw EmailAliasError.conflict
        }
        try await validate(context)
    }

    private func loadConnection(baseUrl: String, context: Context) async throws -> ConnectionState? {
        let payloads = try await loadPayloads(context: context)
            .filter { $0.connection.adapter.adapterId == adapter.adapterId }
        let roots = payloads.filter { $0.credential?.baseUrl == baseUrl }
        guard !roots.isEmpty else { return nil }
        let connectionIds = Set(roots.map(\.connection.connectionId))
        guard connectionIds.count == 1, let connectionId = connectionIds.first else {
            throw EmailAliasError.conflict
        }
        return try assembleConnection(
            payloads.filter { $0.connection.connectionId == connectionId },
            context: context,
        )
    }

    private func requiredConnection(for identity: AliasIdentity, context: Context) async throws -> ConnectionState {
        guard identity.version == UInt32(AliasConnectionSchema.version),
              AliasSyncValidation.canonicalUUID(identity.connectionId) == identity.connectionId
        else { throw EmailAliasError.invalidEncryptedState }
        let matching = try await loadPayloads(context: context)
            .filter { $0.connection.connectionId == identity.connectionId }
        guard !matching.isEmpty else { throw EmailAliasError.conflict }
        return try assembleConnection(matching, context: context)
    }

    private func assembleConnection(
        _ payloads: [AliasConnectionVaultPayload],
        context: Context,
    ) throws -> ConnectionState {
        guard let connection = payloads.first?.connection,
              payloads.allSatisfy({ $0.connection == connection })
        else { throw EmailAliasError.conflict }
        let credentials = Set(payloads.compactMap(\.credential))
        guard credentials.count == 1, let credential = credentials.first else {
            throw EmailAliasError.conflict
        }
        let journal = try AliasJournal.merged(payloads.map(\.journal), connectionId: connection.connectionId)
        return ConnectionState(connection: connection, credential: credential, journal: journal)
    }

    private func loadPayloads(context: Context) async throws -> [AliasConnectionVaultPayload] {
        try await validate(context)
        let ciphers = try await cipherService.fetchAllCiphers()
        var payloads = [AliasConnectionVaultPayload]()
        for cipher in ciphers where cipher.type == .secureNote {
            try await validate(context)
            let view = try await clientService.vault().ciphers().decrypt(cipher: cipher)
            if view.isAliasConnectionCarrier { try payloads.append(AliasConnectionVaultCodec.decode(view)) }
        }
        decryptedPayloads = payloads
        return payloads
    }

    // MARK: - Reconciliation and cached reuse

    private func reconcileLoginBindings(
        aliases: [BitwardenSdk.Alias],
        state: ConnectionState,
        context: Context,
    ) async throws {
        let encryptedCiphers = try await cipherService.fetchAllCiphers().filter { $0.type == .login }
        let ciphers = try await encryptedCiphers.asyncMap { cipher in
            try await clientService.vault().ciphers().decrypt(cipher: cipher)
        }
        let plan = try planAliasReconciliation(
            connectionId: state.connection.connectionId,
            aliases: aliases,
            ciphers: ciphers,
        )
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
        in journal: AliasJournal,
        excluding usedAliases: Set<AliasIdentity>,
    ) throws -> EmailAliasResult? {
        let reduced: AliasJournalState
        do { reduced = try reduceAliasJournal(journal: journal) } catch { throw EmailAliasError.invalidEncryptedState }
        guard reduced.conflicts.isEmpty else { throw EmailAliasError.conflict }
        let hasUnknownCreate = reduced.operations.contains { operation in
            operation.operation == .create
                && (operation.phase == .dispatched || operation.phase == .outcomeUnknown)
        }
        guard let resource = reduced.resources.first(where: { resource in
            !resource.tombstoned
                && resource.lifecycle == .enabled
                && !usedAliases.contains(resource.identity)
        }) else {
            if hasUnknownCreate { throw EmailAliasError.operationOutcomeUnknown }
            return nil
        }
        var result = try result(resource.identity, lifecycle: resource.lifecycle)
        if hasUnknownCreate { result.status = .unknown }
        return result
    }

    private func rejectUncertainCreate(in journal: AliasJournal) throws {
        let reduced = try reduceAliasJournal(journal: journal)
        guard reduced.conflicts.isEmpty else { throw EmailAliasError.conflict }
        guard !reduced.operations.contains(where: { operation in
            operation.operation == .create
                && (operation.phase == .dispatched || operation.phase == .outcomeUnknown)
        }) else { throw EmailAliasError.operationOutcomeUnknown }
    }

    private func boundAliases(context: Context) async throws -> Set<AliasIdentity> {
        let encrypted = try await cipherService.fetchAllCiphers().filter { $0.type == .login }
        var identities = Set<AliasIdentity>()
        for cipher in encrypted {
            try await validate(context)
            let view = try await clientService.vault().ciphers().decrypt(cipher: cipher)
            guard let value = view.login?.aliasReference,
                  let reference = try? parseAliasReference(value: value)
            else { continue }
            identities.insert(AliasIdentity(
                version: reference.version,
                connectionId: reference.connectionId,
                aliasId: reference.aliasId,
                address: reference.address,
            ))
        }
        return identities
    }

    // MARK: - Failure recording

    private func handleCreateFailure(
        _ error: AliasError,
        operationId: String,
        state: inout ConnectionState,
        context: Context,
    ) async throws -> EmailAliasResult {
        try? await recordFailure(FailureRecord(
            error: error,
            operationId: operationId,
            operation: .create,
            target: nil,
        ),
        state: &state,
        context: context)
        if error == .OutcomeUnknown {
            let used = try await boundAliases(context: context)
            if var cached = try cachedAlias(in: state.journal, excluding: used) {
                cached.status = .unknown
                return cached
            }
        }
        throw map(error)
    }

    private func recordFailure(
        _ record: FailureRecord,
        state: inout ConnectionState,
        context: Context,
    ) async throws {
        let outcomeUnknown = record.error == .OutcomeUnknown
        try await appendAndPersist(
            operationId: record.operationId,
            operation: record.operation,
            phase: outcomeUnknown ? .outcomeUnknown : .failed,
            target: record.target,
            lifecycle: record.lifecycle,
            error: outcomeUnknown ? .outcomeUnknown : errorCode(record.error),
            state: &state,
            context: context,
        )
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
            ? adapter.defaultBaseUrl
            : value
        guard let canonical = AliasSyncValidation.canonicalEndpoint(candidate) else {
            throw EmailAliasError.invalidConfiguration
        }
        return canonical
    }

    private func normalizedHostname(_ value: String?) -> String? {
        guard let value else { return nil }
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return normalized.isEmpty ? nil : normalized
    }

    private func makeClient(_ state: ConnectionState) throws -> any AliasClientProtocol {
        try adapter.makeClient(state.connection, state.credential)
    }

    private func result(_ alias: BitwardenSdk.Alias) throws -> EmailAliasResult {
        try result(alias.identity, lifecycle: alias.lifecycle)
    }

    private func result(_ identity: AliasIdentity, lifecycle: AliasLifecycleState) throws -> EmailAliasResult {
        try EmailAliasResult(
            address: identity.address,
            reference: createAliasReference(identity: identity),
            identity: identity,
            status: status(lifecycle),
        )
    }

    private func status(_ lifecycle: AliasLifecycleState) -> EmailAliasLifecycleStatus {
        switch lifecycle {
        case .enabled: .enabled
        case .disabled: .disabled
        case .deleted: .deleted
        }
    }

    private func map(_ error: AliasError) -> EmailAliasError {
        switch error {
        case .VaultLocked: .locked
        case .OutcomeUnknown: .operationOutcomeUnknown
        case .SyncConflict: .conflict
        case .InvalidInput: .invalidConfiguration
        case .ConnectionMissing, .InvalidResponse, .LocalSecurityFailure: .invalidEncryptedState
        default: .providerRejected
        }
    }

    private func errorCode(_ error: AliasError) -> AliasErrorCode {
        switch error {
        case .VaultLocked: .vaultLocked
        case .ConnectionMissing: .connectionMissing
        case .AuthenticationRejected: .authenticationRejected
        case .PermissionDenied: .permissionDenied
        case .CapabilityUnsupported: .capabilityUnsupported
        case .InvalidInput: .invalidInput
        case .NotFound: .notFound
        case .QuotaExhausted: .quotaExhausted
        case .RateLimited: .rateLimited
        case .Offline: .offline
        case .Timeout: .timeout
        case .ServiceUnavailable: .serviceUnavailable
        case .InvalidResponse: .invalidResponse
        case .OutcomeUnknown: .outcomeUnknown
        case .SyncConflict: .syncConflict
        case .LocalSecurityFailure: .localSecurityFailure
        }
    }

    private func clearDecryptedState() {
        decryptedPayloads.removeAll(keepingCapacity: false)
    }
}

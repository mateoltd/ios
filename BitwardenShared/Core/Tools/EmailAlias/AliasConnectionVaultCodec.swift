import BitwardenSdk
import Foundation

// The encrypted carrier mirrors only the canonical provider-neutral SDK contract. Provider
// credentials remain encrypted implementation metadata and never enter references or journals.
// swiftlint:disable file_length

enum AliasConnectionSchema {
    static let carrierName = "bitwarden.alias.connection.v1"
    static let fieldPartSize = 1500
    static let markerField = "bitwarden.alias.connection.marker"
    static let payloadField = "bitwarden.alias.connection.payload"
    static let segmentSize = 60000
    static let version = 1
}

struct AliasConnectionCredential: Codable, Equatable, Hashable, Sendable {
    let token: String
    let baseUrl: String
}

struct AliasConnectionVaultPayload: Equatable, Sendable {
    let version: Int
    let connection: AliasConnection
    var credential: AliasConnectionCredential?
    var journal: AliasJournal
}

enum EmailAliasLifecycleStatus: Equatable, Sendable {
    case enabled
    case disabled
    case deleted
    case unknown
    case conflict
}

struct EmailAliasResult: Equatable, Sendable {
    let address: String
    let reference: String
    let identity: AliasIdentity
    var status: EmailAliasLifecycleStatus
    var journalPersistenceFailed = false

    /// Session owner of decrypted results; never serialized into an alias reference.
    var ownerUserId: String?
}

enum EmailAliasError: Error, Equatable {
    case accountChanged
    case conflict
    case invalidConfiguration
    case invalidEncryptedState
    case locked
    case noCachedAlias
    case operationOutcomeUnknown
    case providerRejected
}

enum AliasSyncValidation {
    static let forbiddenJournalKeys: Set<String> = [
        "authentication",
        "apikey",
        "apitoken",
        "baseurl",
        "credential",
        "endpoint",
        "password",
        "providerspecific",
        "signedsuffix",
        "token",
    ]

    static func validate(_ payload: AliasConnectionVaultPayload) throws {
        let capabilities = payload.connection.adapter.capabilities
        guard payload.version == AliasConnectionSchema.version,
              payload.connection.version == UInt32(AliasConnectionSchema.version),
              payload.journal.version == UInt32(AliasConnectionSchema.version),
              payload.journal.connectionId == payload.connection.connectionId,
              canonicalUUID(payload.connection.connectionId) == payload.connection.connectionId,
              validIdentifier(payload.connection.adapter.adapterId, maxLength: 64),
              capabilities.create,
              capabilities.list,
              capabilities.get,
              capabilities.enableDisable,
              capabilities.delete,
              capabilities.createSendReplyIdentity,
              capabilities.listSendReplyIdentities,
              capabilities.removeSendReplyIdentity,
              capabilities.extensions == Array(Set(capabilities.extensions)).sorted(),
              capabilities.extensions.allSatisfy({ validIdentifier($0, maxLength: 128) }),
              payload.credential.map(valid) ?? true
        else { throw EmailAliasError.invalidEncryptedState }

        do {
            guard try canonicalizeAliasJournal(journal: payload.journal) == payload.journal else {
                throw EmailAliasError.invalidEncryptedState
            }
        } catch {
            throw EmailAliasError.invalidEncryptedState
        }
    }

    static func containsForbiddenJournalKey(_ value: Any) -> Bool {
        if let values = value as? [Any] {
            return values.contains(where: containsForbiddenJournalKey)
        }
        guard let object = value as? [String: Any] else { return false }
        return object.contains { key, child in
            let normalized = key
                .replacingOccurrences(of: "-", with: "")
                .replacingOccurrences(of: "_", with: "")
                .lowercased()
            return forbiddenJournalKeys.contains(normalized) || containsForbiddenJournalKey(child)
        }
    }

    static func canonicalEndpoint(_ value: String) -> String? {
        guard var components = URLComponents(string: value.trimmingCharacters(in: .whitespacesAndNewlines)),
              let host = components.host,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              components.scheme?.lowercased() == "https"
              || (components.scheme?.lowercased() == "http" && isLoopback(host))
        else { return nil }
        components.scheme = components.scheme?.lowercased()
        components.host = host.lowercased()
        while components.path.hasSuffix("/") {
            components.path.removeLast()
        }
        components.path.append("/")
        return components.url?.absoluteString
    }

    static func canonicalUUID(_ value: String) -> String? {
        guard let uuid = UUID(uuidString: value), uuid.uuidString.lowercased() == value.lowercased() else {
            return nil
        }
        return uuid.uuidString.lowercased()
    }

    private static func isLoopback(_ hostname: String) -> Bool {
        let host = hostname.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if host == "localhost" || host.hasSuffix(".localhost") || host == "::1" { return true }
        let octets = host.split(separator: ".", omittingEmptySubsequences: false)
        return octets.count == 4 && octets.first == "127" && octets.allSatisfy { octet in
            guard let value = UInt8(octet) else { return false }
            return String(value) == octet
        }
    }

    private static func valid(_ credential: AliasConnectionCredential) -> Bool {
        let token = credential.token.trimmingCharacters(in: .whitespacesAndNewlines)
        return !token.isEmpty
            && token.count <= 16384
            && !token.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
            && canonicalEndpoint(credential.baseUrl) == credential.baseUrl
    }

    private static func validIdentifier(_ value: String, maxLength: Int) -> Bool {
        guard !value.isEmpty, value.utf8.count <= maxLength else { return false }
        return value.utf8.allSatisfy { byte in
            (97 ... 122).contains(byte)
                || (48 ... 57).contains(byte)
                || byte == 46
                || byte == 45
        }
    }
}

extension CipherView {
    var isAliasConnectionCarrier: Bool {
        organizationId == nil
            && type == .secureNote
            && name == AliasConnectionSchema.carrierName
            && fields?.contains(where: { field in
                field.type == .text
                    && field.name == AliasConnectionSchema.markerField
                    && field.value == String(AliasConnectionSchema.version)
            }) == true
    }
}

extension CipherListView {
    /// The list view omits fields, so candidates are decrypted before being excluded.
    var isAliasConnectionCarrierCandidate: Bool {
        guard organizationId == nil, name == AliasConnectionSchema.carrierName else { return false }
        if case .secureNote = type { return true }
        return false
    }
}

/// Removes only authenticated encrypted connection carriers. Same-named user notes remain visible.
func excludingAliasConnectionCarriers(
    _ listViews: [CipherListView],
    encryptedCiphers: [Cipher],
    decrypt: (Cipher) async throws -> CipherView,
) async -> [CipherListView] {
    var visible = [CipherListView]()
    visible.reserveCapacity(listViews.count)
    for listView in listViews {
        guard listView.isAliasConnectionCarrierCandidate else {
            visible.append(listView)
            continue
        }
        guard let encrypted = encryptedCiphers.first(where: { $0.id == listView.id }),
              let view = try? await decrypt(encrypted),
              !view.isAliasConnectionCarrier
        else {
            continue
        }
        visible.append(listView)
    }
    return visible
}

// MARK: - Canonical SDK journal helpers

extension AliasJournal {
    static func empty(connectionId: String) throws -> AliasJournal {
        do {
            return try canonicalizeAliasJournal(journal: AliasJournal(
                version: UInt32(AliasConnectionSchema.version),
                connectionId: connectionId,
                events: [],
            ))
        } catch {
            throw EmailAliasError.invalidEncryptedState
        }
    }

    static func merged(_ journals: [AliasJournal], connectionId: String) throws -> AliasJournal {
        var result = try empty(connectionId: connectionId)
        do {
            for journal in journals {
                result = try mergeAliasJournals(left: result, right: journal)
            }
            return result
        } catch let error as AliasError where error == .SyncConflict {
            throw EmailAliasError.conflict
        } catch {
            throw EmailAliasError.invalidEncryptedState
        }
    }

    mutating func append(
        replicaId: String,
        operationId: String,
        operation: AliasOperationKind,
        phase: AliasOperationPhase,
        target: AliasIdentity? = nil,
        lifecycle: AliasLifecycleState? = nil,
        error: AliasErrorCode? = nil,
    ) throws -> AliasJournalEvent {
        var observed = [String: UInt64]()
        for event in events {
            observed[event.replicaId] = max(observed[event.replicaId] ?? 0, event.sequence)
            for entry in event.causal {
                observed[entry.replicaId] = max(observed[entry.replicaId] ?? 0, entry.sequence)
            }
        }
        let sequence = (observed[replicaId] ?? 0) + 1
        let causal = observed
            .filter { $0.value > 0 }
            .map { AliasCausalEntry(replicaId: $0.key, sequence: $0.value) }
            .sorted { $0.replicaId < $1.replicaId }
        let event = AliasJournalEvent(
            version: UInt32(AliasConnectionSchema.version),
            eventId: UUID().uuidString.lowercased(),
            operationId: operationId,
            replicaId: replicaId,
            sequence: sequence,
            causal: causal,
            operation: operation,
            phase: phase,
            target: target,
            lifecycle: lifecycle,
            error: error,
        )
        do {
            self = try canonicalizeAliasJournal(journal: AliasJournal(
                version: version,
                connectionId: connectionId,
                events: events + [event],
            ))
            return event
        } catch let aliasError as AliasError where aliasError == .SyncConflict {
            throw EmailAliasError.conflict
        } catch {
            throw EmailAliasError.invalidEncryptedState
        }
    }
}

// MARK: - Encrypted carrier codec

enum AliasConnectionVaultCodec {
    static func decode(_ cipher: CipherView) throws -> AliasConnectionVaultPayload {
        guard cipher.isAliasConnectionCarrier else { throw EmailAliasError.invalidEncryptedState }
        let parts = (cipher.fields ?? [])
            .filter { field in
                field.type == .hidden
                    && (field.name?.hasPrefix("\(AliasConnectionSchema.payloadField).") ?? false)
            }
            .sorted { ($0.name ?? "") < ($1.name ?? "") }
        guard !parts.isEmpty,
              parts.enumerated().allSatisfy({ index, field in
                  field.name == "\(AliasConnectionSchema.payloadField).\(String(format: "%04d", index))"
                      && field.value != nil
                      && (field.value?.count ?? 0) <= AliasConnectionSchema.fieldPartSize
              })
        else { throw EmailAliasError.invalidEncryptedState }
        let encoded = parts.compactMap(\.value).joined()
        guard encoded.count <= AliasConnectionSchema.segmentSize,
              let data = encoded.data(using: .utf8),
              !data.isEmpty,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { throw EmailAliasError.invalidEncryptedState }
        try validateShape(object)
        guard let journal = object["journal"], !AliasSyncValidation.containsForbiddenJournalKey(journal) else {
            throw EmailAliasError.invalidEncryptedState
        }
        let payload = try PayloadDTO.decode(data).model()
        try AliasSyncValidation.validate(payload)
        return payload
    }

    // swiftlint:disable:next function_body_length
    static func encode(_ payload: AliasConnectionVaultPayload, date: Date = .now) throws -> CipherView {
        try AliasSyncValidation.validate(payload)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(PayloadDTO(payload))
        guard let encoded = String(data: data, encoding: .utf8),
              encoded.count <= AliasConnectionSchema.segmentSize
        else { throw EmailAliasError.invalidEncryptedState }
        var fields = [
            FieldView(
                name: AliasConnectionSchema.markerField,
                value: String(AliasConnectionSchema.version),
                type: .text,
                linkedId: nil,
            ),
        ]
        var offset = encoded.startIndex
        var index = 0
        while offset < encoded.endIndex {
            let end = encoded.index(offset, offsetBy: AliasConnectionSchema.fieldPartSize, limitedBy: encoded.endIndex)
                ?? encoded.endIndex
            fields.append(FieldView(
                name: "\(AliasConnectionSchema.payloadField).\(String(format: "%04d", index))",
                value: String(encoded[offset ..< end]),
                type: .hidden,
                linkedId: nil,
            ))
            offset = end
            index += 1
        }
        return CipherView(
            id: nil,
            organizationId: nil,
            folderId: nil,
            collectionIds: [],
            key: nil,
            name: AliasConnectionSchema.carrierName,
            notes: nil,
            type: .secureNote,
            login: nil,
            identity: nil,
            card: nil,
            secureNote: SecureNoteView(type: .generic),
            sshKey: nil,
            bankAccount: nil,
            driversLicense: nil,
            passport: nil,
            favorite: false,
            reprompt: .password,
            organizationUseTotp: false,
            edit: true,
            permissions: nil,
            viewPassword: true,
            localData: nil,
            attachments: nil,
            attachmentDecryptionFailures: nil,
            fields: fields,
            passwordHistory: nil,
            creationDate: date,
            deletedDate: nil,
            revisionDate: date,
            archivedDate: nil,
            partial: false, // Newly created local cipher; not a server-restricted view.
        )
    }

    private static func validateShape(_ object: [String: Any]) throws {
        try requireKeys(object, required: ["version", "connection", "journal"], optional: ["credential"])
        let connection = try dictionary(object["connection"])
        try requireKeys(connection, required: ["version", "connectionId", "adapter"])
        let adapter = try dictionary(connection["adapter"])
        try requireKeys(adapter, required: ["adapterId", "capabilities"])
        let capabilities = try dictionary(adapter["capabilities"])
        try requireKeys(capabilities, required: [
            "create", "list", "get", "enableDisable", "delete", "createSendReplyIdentity",
            "listSendReplyIdentities", "removeSendReplyIdentity", "extensions",
        ])
        if let credential = object["credential"], !(credential is NSNull) {
            try requireKeys(dictionary(credential), required: ["token", "baseUrl"])
        }
        let journal = try dictionary(object["journal"])
        try requireKeys(journal, required: ["version", "connectionId", "events"])
        guard let events = journal["events"] as? [Any] else { throw EmailAliasError.invalidEncryptedState }
        for value in events {
            let event = try dictionary(value)
            try requireKeys(
                event,
                required: [
                    "version", "eventId", "operationId", "replicaId", "sequence", "causal", "operation", "phase",
                ],
                optional: ["target", "lifecycle", "error"],
            )
            guard let causal = event["causal"] as? [Any] else { throw EmailAliasError.invalidEncryptedState }
            for entry in causal {
                try requireKeys(dictionary(entry), required: ["replicaId", "sequence"])
            }
            if let target = event["target"], !(target is NSNull) {
                try requireKeys(
                    dictionary(target),
                    required: ["version", "connectionId", "aliasId", "address"],
                )
            }
        }
    }

    private static func dictionary(_ value: Any?) throws -> [String: Any] {
        guard let result = value as? [String: Any] else { throw EmailAliasError.invalidEncryptedState }
        return result
    }

    private static func requireKeys(
        _ object: [String: Any],
        required: Set<String>,
        optional: Set<String> = [],
    ) throws {
        let keys = Set(object.keys)
        guard required.isSubset(of: keys), keys.isSubset(of: required.union(optional)) else {
            throw EmailAliasError.invalidEncryptedState
        }
    }
}

// MARK: - Strict persistence DTOs

// Codable persistence mirrors require computed projections alongside explicit initializers.
// swiftlint:disable type_contents_order
private struct PayloadDTO: Codable {
    let version: Int
    let connection: ConnectionDTO
    let credential: AliasConnectionCredential?
    let journal: JournalDTO

    init(_ payload: AliasConnectionVaultPayload) {
        version = payload.version
        connection = ConnectionDTO(payload.connection)
        credential = payload.credential
        journal = JournalDTO(payload.journal)
    }

    func model() throws -> AliasConnectionVaultPayload {
        try AliasConnectionVaultPayload(
            version: version,
            connection: connection.model,
            credential: credential,
            journal: journal.model(),
        )
    }

    static func decode(_ data: Data) throws -> PayloadDTO {
        do {
            return try JSONDecoder().decode(PayloadDTO.self, from: data)
        } catch {
            throw EmailAliasError.invalidEncryptedState
        }
    }
}

private struct ConnectionDTO: Codable {
    let version: UInt32
    let connectionId: String
    let adapter: AdapterDTO

    init(_ value: AliasConnection) {
        version = value.version
        connectionId = value.connectionId
        adapter = AdapterDTO(value.adapter)
    }

    var model: AliasConnection {
        AliasConnection(version: version, connectionId: connectionId, adapter: adapter.model)
    }
}

private struct AdapterDTO: Codable {
    let adapterId: String
    let capabilities: CapabilitiesDTO

    init(_ value: AliasAdapterDescriptor) {
        adapterId = value.adapterId
        capabilities = CapabilitiesDTO(value.capabilities)
    }

    var model: AliasAdapterDescriptor {
        AliasAdapterDescriptor(adapterId: adapterId, capabilities: capabilities.model)
    }
}

private struct CapabilitiesDTO: Codable {
    let create: Bool
    let list: Bool
    let get: Bool
    let enableDisable: Bool
    let delete: Bool
    let createSendReplyIdentity: Bool
    let listSendReplyIdentities: Bool
    let removeSendReplyIdentity: Bool
    let extensions: [String]

    init(_ value: AliasProviderCapabilities) {
        create = value.create
        list = value.list
        get = value.get
        enableDisable = value.enableDisable
        delete = value.delete
        createSendReplyIdentity = value.createSendReplyIdentity
        listSendReplyIdentities = value.listSendReplyIdentities
        removeSendReplyIdentity = value.removeSendReplyIdentity
        extensions = value.extensions
    }

    var model: AliasProviderCapabilities {
        AliasProviderCapabilities(
            create: create,
            list: list,
            get: get,
            enableDisable: enableDisable,
            delete: delete,
            createSendReplyIdentity: createSendReplyIdentity,
            listSendReplyIdentities: listSendReplyIdentities,
            removeSendReplyIdentity: removeSendReplyIdentity,
            extensions: extensions,
        )
    }
}

private struct JournalDTO: Codable {
    let version: UInt32
    let connectionId: String
    let events: [EventDTO]

    init(_ value: AliasJournal) {
        version = value.version
        connectionId = value.connectionId
        events = value.events.map(EventDTO.init)
    }

    func model() throws -> AliasJournal {
        try AliasJournal(
            version: version,
            connectionId: connectionId,
            events: events.map { try $0.model() },
        )
    }
}

private struct EventDTO: Codable {
    let version: UInt32
    let eventId: String
    let operationId: String
    let replicaId: String
    let sequence: UInt64
    let causal: [CausalDTO]
    let operation: String
    let phase: String
    let target: IdentityDTO?
    let lifecycle: String?
    let error: String?

    init(_ value: AliasJournalEvent) {
        version = value.version
        eventId = value.eventId
        operationId = value.operationId
        replicaId = value.replicaId
        sequence = value.sequence
        causal = value.causal.map(CausalDTO.init)
        operation = value.operation.persistenceValue
        phase = value.phase.persistenceValue
        target = value.target.map(IdentityDTO.init)
        lifecycle = value.lifecycle?.persistenceValue
        error = value.error?.persistenceValue
    }

    func model() throws -> AliasJournalEvent {
        guard let operation = AliasOperationKind(persistenceValue: operation),
              let phase = AliasOperationPhase(persistenceValue: phase)
        else { throw EmailAliasError.invalidEncryptedState }
        let lifecycleValue: AliasLifecycleState?
        if let lifecycle {
            guard let value = AliasLifecycleState(persistenceValue: lifecycle) else {
                throw EmailAliasError.invalidEncryptedState
            }
            lifecycleValue = value
        } else {
            lifecycleValue = nil
        }
        let errorValue: AliasErrorCode?
        if let error {
            guard let value = AliasErrorCode(persistenceValue: error) else {
                throw EmailAliasError.invalidEncryptedState
            }
            errorValue = value
        } else {
            errorValue = nil
        }
        return AliasJournalEvent(
            version: version,
            eventId: eventId,
            operationId: operationId,
            replicaId: replicaId,
            sequence: sequence,
            causal: causal.map(\.model),
            operation: operation,
            phase: phase,
            target: target?.model,
            lifecycle: lifecycleValue,
            error: errorValue,
        )
    }
}

private struct CausalDTO: Codable {
    let replicaId: String
    let sequence: UInt64

    init(_ value: AliasCausalEntry) {
        replicaId = value.replicaId
        sequence = value.sequence
    }

    var model: AliasCausalEntry { AliasCausalEntry(replicaId: replicaId, sequence: sequence) }
}

private struct IdentityDTO: Codable {
    let version: UInt32
    let connectionId: String
    let aliasId: String
    let address: String

    init(_ value: AliasIdentity) {
        version = value.version
        connectionId = value.connectionId
        aliasId = value.aliasId
        address = value.address
    }

    var model: AliasIdentity {
        AliasIdentity(version: version, connectionId: connectionId, aliasId: aliasId, address: address)
    }
}

private extension AliasOperationKind {
    init?(persistenceValue: String) {
        switch persistenceValue {
        case "create": self = .create
        case "list": self = .list
        case "get": self = .get
        case "enable": self = .enable
        case "disable": self = .disable
        case "delete": self = .delete
        case "create-send-reply-identity": self = .createSendReplyIdentity
        case "list-send-reply-identities": self = .listSendReplyIdentities
        case "remove-send-reply-identity": self = .removeSendReplyIdentity
        case "set-send-reply-blocked": self = .setSendReplyBlocked
        case "reconcile": self = .reconcile
        default: return nil
        }
    }

    var persistenceValue: String {
        switch self {
        case .create: "create"
        case .list: "list"
        case .get: "get"
        case .enable: "enable"
        case .disable: "disable"
        case .delete: "delete"
        case .createSendReplyIdentity: "create-send-reply-identity"
        case .listSendReplyIdentities: "list-send-reply-identities"
        case .removeSendReplyIdentity: "remove-send-reply-identity"
        case .setSendReplyBlocked: "set-send-reply-blocked"
        case .reconcile: "reconcile"
        }
    }
}

private extension AliasOperationPhase {
    init?(persistenceValue: String) {
        switch persistenceValue {
        case "prepared": self = .prepared
        case "dispatched": self = .dispatched
        case "acknowledged": self = .acknowledged
        case "outcome-unknown": self = .outcomeUnknown
        case "failed": self = .failed
        default: return nil
        }
    }

    var persistenceValue: String {
        switch self {
        case .prepared: "prepared"
        case .dispatched: "dispatched"
        case .acknowledged: "acknowledged"
        case .outcomeUnknown: "outcome-unknown"
        case .failed: "failed"
        }
    }
}

private extension AliasLifecycleState {
    init?(persistenceValue: String) {
        switch persistenceValue {
        case "enabled": self = .enabled
        case "disabled": self = .disabled
        case "deleted": self = .deleted
        default: return nil
        }
    }

    var persistenceValue: String {
        switch self {
        case .enabled: "enabled"
        case .disabled: "disabled"
        case .deleted: "deleted"
        }
    }
}

private extension AliasErrorCode {
    init?(persistenceValue: String) {
        switch persistenceValue {
        case "vault-locked": self = .vaultLocked
        case "connection-missing": self = .connectionMissing
        case "authentication-rejected": self = .authenticationRejected
        case "permission-denied": self = .permissionDenied
        case "capability-unsupported": self = .capabilityUnsupported
        case "invalid-input": self = .invalidInput
        case "not-found": self = .notFound
        case "quota-exhausted": self = .quotaExhausted
        case "rate-limited": self = .rateLimited
        case "offline": self = .offline
        case "timeout": self = .timeout
        case "service-unavailable": self = .serviceUnavailable
        case "invalid-response": self = .invalidResponse
        case "outcome-unknown": self = .outcomeUnknown
        case "sync-conflict": self = .syncConflict
        case "local-security-failure": self = .localSecurityFailure
        default: return nil
        }
    }

    var persistenceValue: String {
        switch self {
        case .vaultLocked: "vault-locked"
        case .connectionMissing: "connection-missing"
        case .authenticationRejected: "authentication-rejected"
        case .permissionDenied: "permission-denied"
        case .capabilityUnsupported: "capability-unsupported"
        case .invalidInput: "invalid-input"
        case .notFound: "not-found"
        case .quotaExhausted: "quota-exhausted"
        case .rateLimited: "rate-limited"
        case .offline: "offline"
        case .timeout: "timeout"
        case .serviceUnavailable: "service-unavailable"
        case .invalidResponse: "invalid-response"
        case .outcomeUnknown: "outcome-unknown"
        case .syncConflict: "sync-conflict"
        case .localSecurityFailure: "local-security-failure"
        }
    }
}

// swiftlint:enable type_contents_order

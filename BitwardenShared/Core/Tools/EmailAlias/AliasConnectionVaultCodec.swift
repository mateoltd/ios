import BitwardenSdk
import Foundation

// This file keeps the shared schema, validation, and codec together so their invariants remain local.
// swiftlint:disable file_length

// MARK: - Shared alias schema v1

enum AliasConnectionSchema {
    static let carrierName = "bitwarden.alias.connection.v1"
    static let markerField = "bitwarden.alias.connection.marker"
    static let payloadField = "bitwarden.alias.connection.payload"
    static let fieldPartSize = 1500
    static let segmentSize = 60000
    static let version = 1
}

struct AliasProviderConnection: Codable, Equatable, Sendable {
    let provider: String
    let providerInstance: String
    let connectionId: String

    init(providerInstance: String, connectionId: String) {
        provider = "simplelogin"
        self.providerInstance = providerInstance
        self.connectionId = connectionId
    }
}

struct AliasConnectionCredential: Codable, Equatable, Hashable, Sendable {
    let token: String
    let baseUrl: String
}

struct EmailAliasIdentity: Codable, Equatable, Hashable, Sendable {
    let version: Int
    let provider: String
    let providerInstance: String
    let connectionId: String
    let aliasId: String
    let address: String

    var sdkReference: AliasReference? {
        guard version == AliasConnectionSchema.version,
              provider == "simplelogin",
              let aliasId = UInt64(aliasId),
              aliasId > 0,
              !address.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else { return nil }
        let reference = AliasReference(
            version: UInt32(version),
            provider: .simpleLogin,
            providerInstance: providerInstance,
            connectionId: connectionId,
            aliasId: aliasId,
            address: address,
        )
        guard (try? serializeAliasReference(reference: reference)) != nil else { return nil }
        return reference
    }

    init(
        version: Int,
        provider: String,
        providerInstance: String,
        connectionId: String,
        aliasId: String,
        address: String,
    ) {
        self.version = version
        self.provider = provider
        self.providerInstance = providerInstance
        self.connectionId = connectionId
        self.aliasId = aliasId
        self.address = address
    }

    init(alias: BitwardenSdk.Alias, connection: AliasProviderConnection) {
        version = AliasConnectionSchema.version
        provider = connection.provider
        providerInstance = connection.providerInstance
        connectionId = connection.connectionId
        aliasId = String(alias.id)
        address = alias.email
    }
}

struct AliasProviderSnapshot: Codable, Equatable, Sendable {
    let alias: EmailAliasIdentity
    let enabled: Bool
    var name: String?
    var note: String?
    var mailboxIds: [UInt64]?
    var pgpDisabled: Bool?
    var pinned: Bool?

    init(alias: BitwardenSdk.Alias, connection: AliasProviderConnection) {
        self.alias = EmailAliasIdentity(alias: alias, connection: connection)
        enabled = alias.enabled
        name = alias.name
        note = alias.note
        mailboxIds = alias.mailboxes.map(\.id)
        pgpDisabled = alias.disablePgp
        pinned = alias.pinned
    }
}

struct AliasCreateIntent: Codable, Equatable, Sendable {
    let kind: String
    var hostname: String?
    var mode: String?
    var note: String?
}

struct AliasProviderOperation: Codable, Equatable, Sendable {
    let operation: String
    var connection: AliasProviderConnection?
    var request: AliasCreateIntent?
    var alias: EmailAliasIdentity?
}

struct AliasSyncEvent: Codable, Equatable, Sendable {
    let version: Int
    let id: String
    let replicaId: String
    let clock: [String: Int]
    let kind: String
    var connection: AliasProviderConnection?
    var value: AliasProviderOperation?
    var operationId: String?
    var snapshot: AliasProviderSnapshot?
    var reason: String?
    var cipherId: String?
    var expectedAliasKey: String?
    var alias: EmailAliasIdentity?
    var conflictId: String?
    var chosenEventId: String?
}

struct AliasSyncDocument: Codable, Equatable, Sendable {
    let version: Int
    var replicaId: String
    var clock: [String: Int]
    var events: [AliasSyncEvent]

    init(replicaId: String) {
        version = AliasConnectionSchema.version
        self.replicaId = replicaId
        clock = [:]
        events = []
    }

    mutating func append(
        kind: String,
        connection: AliasProviderConnection? = nil,
        value: AliasProviderOperation? = nil,
        operationId: String? = nil,
        snapshot: AliasProviderSnapshot? = nil,
        reason: String? = nil,
        cipherId: String? = nil,
        expectedAliasKey: String? = nil,
        alias: EmailAliasIdentity? = nil,
        conflictId: String? = nil,
        chosenEventId: String? = nil,
    ) throws -> AliasSyncEvent {
        guard AliasSyncValidation.eventKinds.contains(kind) else {
            throw EmailAliasError.invalidEncryptedState
        }
        let counter = (clock[replicaId] ?? 0) + 1
        clock[replicaId] = counter
        let event = AliasSyncEvent(
            version: AliasConnectionSchema.version,
            id: UUID().uuidString.lowercased(),
            replicaId: replicaId,
            clock: clock,
            kind: kind,
            connection: connection,
            value: value,
            operationId: operationId,
            snapshot: snapshot,
            reason: reason,
            cipherId: cipherId,
            expectedAliasKey: expectedAliasKey,
            alias: alias,
            conflictId: conflictId,
            chosenEventId: chosenEventId,
        )
        events.append(event)
        return event
    }
}

struct AliasConnectionVaultPayload: Codable, Equatable, Sendable {
    let version: Int
    let connection: AliasProviderConnection
    var credential: AliasConnectionCredential?
    var sync: AliasSyncDocument
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
    let identity: EmailAliasIdentity
    var status: EmailAliasLifecycleStatus
    var journalPersistenceFailed: Bool = false
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
    static let eventKinds: Set<String> = [
        "connection-upsert",
        "connection-remove",
        "provider-operation",
        "provider-dispatched",
        "provider-ack",
        "provider-unknown",
        "provider-failed",
        "provider-observe",
        "reference-set",
        "reference-clear",
        "conflict-resolve",
    ]

    static let failureReasons: Set<String> = [
        "invalid-credentials",
        "forbidden",
        "not-found",
        "rate-limited",
        "invalid-response",
    ]

    static let forbiddenJournalKeys: Set<String> = [
        "authentication",
        "api_key",
        "api_token",
        "apikey",
        "apitoken",
        "password",
        "signed_suffix",
        "signedsuffix",
        "token",
    ]

    static func validate(_ payload: AliasConnectionVaultPayload) throws {
        guard payload.version == AliasConnectionSchema.version,
              payload.sync.version == AliasConnectionSchema.version,
              valid(payload.connection),
              canonicalUUID(payload.sync.replicaId) == payload.sync.replicaId,
              payload.sync.clock.allSatisfy({ canonicalUUID($0.key) == $0.key && $0.value >= 0 }),
              payload.credential.map({ credential in
                  !credential.token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                      && canonicalProviderInstance(credential.baseUrl) == payload.connection.providerInstance
              }) ?? true
        else { throw EmailAliasError.invalidEncryptedState }

        var eventIds = Set<String>()
        for event in payload.sync.events {
            guard event.version == AliasConnectionSchema.version,
                  eventKinds.contains(event.kind),
                  canonicalUUID(event.id) == event.id,
                  canonicalUUID(event.replicaId) == event.replicaId,
                  eventIds.insert(event.id).inserted,
                  event.clock.allSatisfy({ canonicalUUID($0.key) == $0.key && $0.value >= 0 }),
                  event.clock[event.replicaId, default: 0] >= 1,
                  event.clock.allSatisfy({ payload.sync.clock[$0.key, default: 0] >= $0.value }),
                  valid(event)
            else { throw EmailAliasError.invalidEncryptedState }
        }
    }

    private static func valid(_ connection: AliasProviderConnection) -> Bool {
        connection.provider == "simplelogin"
            && canonicalUUID(connection.connectionId) == connection.connectionId
            && canonicalProviderInstance(connection.providerInstance) == connection.providerInstance
    }

    private static func valid(_ identity: EmailAliasIdentity) -> Bool {
        identity.sdkReference != nil
            && canonicalUUID(identity.connectionId) == identity.connectionId
            && canonicalProviderInstance(identity.providerInstance) == identity.providerInstance
    }

    private static func valid(_ snapshot: AliasProviderSnapshot) -> Bool {
        valid(snapshot.alias)
            && (snapshot.mailboxIds?.allSatisfy { $0 > 0 } ?? true)
    }

    private static func valid(_ event: AliasSyncEvent) -> Bool {
        switch event.kind {
        case "connection-remove", "connection-upsert":
            event.connection.map(valid) == true
        case "provider-operation":
            event.value.map(valid) == true
        case "provider-dispatched", "provider-unknown":
            event.operationId.map { canonicalUUID($0) == $0 } == true
        case "provider-ack":
            event.operationId.map { canonicalUUID($0) == $0 } == true
                && (event.snapshot.map(valid) ?? true)
        case "provider-failed":
            event.operationId.map { canonicalUUID($0) == $0 } == true
                && event.reason.map(failureReasons.contains) == true
        case "provider-observe":
            event.snapshot.map(valid) == true
        case "reference-set":
            !(event.cipherId?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
                && event.alias.map(valid) == true
                && event.expectedAliasKey.map { !$0.isEmpty } != false
        case "reference-clear":
            !(event.cipherId?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
                && event.expectedAliasKey.map { !$0.isEmpty } != false
        case "conflict-resolve":
            !(event.conflictId?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
                && event.chosenEventId.map { canonicalUUID($0) == $0 } == true
        default:
            false
        }
    }

    private static func valid(_ operation: AliasProviderOperation) -> Bool {
        switch operation.operation {
        case "create":
            guard operation.connection.map(valid) == true,
                  let request = operation.request,
                  request.kind == "random" || request.kind == "custom",
                  request.mode == nil || request.mode == "uuid" || request.mode == "word"
            else { return false }
            return true
        case "delete", "disable", "enable", "update":
            return operation.alias.map(valid) == true
        default:
            return false
        }
    }

    static func containsForbiddenJournalKey(_ value: Any) -> Bool {
        if let values = value as? [Any] {
            return values.contains(where: containsForbiddenJournalKey)
        }
        guard let object = value as? [String: Any] else { return false }
        return object.contains { key, child in
            let normalized = key.replacingOccurrences(of: "-", with: "").lowercased()
            return forbiddenJournalKeys.contains(normalized) || containsForbiddenJournalKey(child)
        }
    }

    static func canonicalUUID(_ value: String) -> String? {
        guard let uuid = UUID(uuidString: value), uuid.uuidString.lowercased() == value.lowercased() else {
            return nil
        }
        return uuid.uuidString.lowercased()
    }

    static func canonicalProviderInstance(_ value: String) -> String? {
        guard var components = URLComponents(string: value),
              let host = components.host,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              components.scheme == "https" || (components.scheme == "http" && host == "127.0.0.1")
        else { return nil }
        components.scheme = components.scheme?.lowercased()
        components.host = host.lowercased()
        while components.path.hasSuffix("/") {
            components.path.removeLast()
        }
        components.path.append("/")
        return components.url?.absoluteString
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
    /// A cheap list-view prefilter. The SDK list view intentionally omits custom fields, so callers
    /// must decrypt a matching cipher and verify `CipherView.isAliasConnectionCarrier` before
    /// suppressing it from a user-facing surface.
    var isAliasConnectionCarrierCandidate: Bool {
        guard organizationId == nil, name == AliasConnectionSchema.carrierName else { return false }
        if case .secureNote = type { return true }
        return false
    }
}

/// Removes only exact encrypted alias carriers. A same-named ordinary secure note remains visible.
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
            // Fail closed for a reserved candidate that cannot be authenticated by its marker.
            continue
        }
        visible.append(listView)
    }
    return visible
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
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let sync = object["sync"],
              !AliasSyncValidation.containsForbiddenJournalKey(sync)
        else {
            throw EmailAliasError.invalidEncryptedState
        }
        let payload = try JSONDecoder().decode(AliasConnectionVaultPayload.self, from: data)
        try AliasSyncValidation.validate(payload)
        return payload
    }

    // swiftlint:disable:next function_body_length
    static func encode(_ payload: AliasConnectionVaultPayload, date: Date = .now) throws -> CipherView {
        try AliasSyncValidation.validate(payload)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(payload)
        guard let encoded = String(data: data, encoding: .utf8),
              encoded.count <= AliasConnectionSchema.segmentSize
        else {
            throw EmailAliasError.invalidEncryptedState
        }
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
        )
    }
}

extension AliasSyncDocument {
    static func merged(_ documents: [AliasSyncDocument], replicaId: String) throws -> AliasSyncDocument {
        var result = AliasSyncDocument(replicaId: replicaId)
        var eventsById = [String: AliasSyncEvent]()
        for document in documents {
            guard document.version == AliasConnectionSchema.version else {
                throw EmailAliasError.invalidEncryptedState
            }
            for (key, counter) in document.clock {
                result.clock[key] = max(result.clock[key] ?? 0, counter)
            }
            for event in document.events {
                if let existing = eventsById[event.id], existing != event {
                    throw EmailAliasError.conflict
                }
                eventsById[event.id] = event
            }
        }
        result.events = eventsById.values.sorted { leftEvent, rightEvent in
            if leftEvent.clock == rightEvent.clock { return leftEvent.id < rightEvent.id }
            let left = leftEvent.clock.values.reduce(0, +)
            let right = rightEvent.clock.values.reduce(0, +)
            return left == right ? leftEvent.id < rightEvent.id : left < right
        }
        return result
    }
}

import BitwardenSdk
import Foundation

extension AliasAdapterRegistration {
    static let simpleLogin = AliasAdapterRegistration(
        adapterId: SimpleLoginAliasAdapter.adapterId,
        defaultBaseUrl: "https://app.simplelogin.io/",
        makeConnection: SimpleLoginAliasAdapter.makeConnection,
        makeClient: { connection, credential in
            try AliasClient(adapter: SimpleLoginAliasAdapter(connection: connection, credential: credential))
        },
    )
}

/// Runtime-only provider implementation behind the provider-neutral SDK callback boundary.
/// Endpoint, credential, native payloads, and provider failures never leave this file.
final class SimpleLoginAliasAdapter: AliasProviderAdapter, @unchecked Sendable {
    private enum Constants {
        static let contactLookupPageLimit = 32
        static let pageSize = 20
        static let toggleAttemptLimit = 3
    }

    static let adapterId = "simplelogin"

    static let capabilities = AliasProviderCapabilities(
        create: true,
        list: true,
        get: true,
        enableDisable: true,
        delete: true,
        createSendReplyIdentity: true,
        listSendReplyIdentities: true,
        removeSendReplyIdentity: true,
        extensions: ["send-reply.block"],
    )

    private let baseUrl: URL
    private let connection: AliasConnection
    private let token: String
    private let transport: AliasHTTPTransport

    convenience init(connection: AliasConnection, credential: AliasConnectionCredential) throws {
        try self.init(connection: connection, credential: credential, transport: AliasHTTPTransport())
    }

    convenience init(
        connection: AliasConnection,
        credential: AliasConnectionCredential,
        session: URLSession,
    ) throws {
        try self.init(
            connection: connection,
            credential: credential,
            transport: AliasHTTPTransport(session: session),
        )
    }

    private init(
        connection: AliasConnection,
        credential: AliasConnectionCredential,
        transport: AliasHTTPTransport,
    ) throws {
        guard connection.version == UInt32(AliasConnectionSchema.version),
              connection.adapter.adapterId == Self.adapterId,
              connection.adapter.capabilities == Self.capabilities,
              AliasSyncValidation.canonicalUUID(connection.connectionId) == connection.connectionId,
              let canonical = AliasSyncValidation.canonicalEndpoint(credential.baseUrl),
              canonical == credential.baseUrl,
              let baseUrl = URL(string: canonical)
        else { throw AliasError.InvalidInput }
        let token = credential.token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty,
              token.count <= 16384,
              !token.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else { throw AliasError.InvalidInput }
        self.baseUrl = baseUrl
        self.connection = connection
        self.token = token
        self.transport = transport
    }

    static func makeConnection(connectionId: String) -> AliasConnection {
        AliasConnection(
            version: UInt32(AliasConnectionSchema.version),
            connectionId: connectionId,
            adapter: AliasAdapterDescriptor(adapterId: adapterId, capabilities: capabilities),
        )
    }

    func descriptor() throws -> AliasAdapterDescriptor { connection.adapter }

    func connectionId() throws -> String { connection.connectionId }

    func create(request value: CreateAliasRequest) async throws -> BitwardenSdk.Alias {
        let query = value.hostname.map { [URLQueryItem(name: "hostname", value: $0)] } ?? []
        let json = try await request(
            method: "POST",
            path: "api/alias/random/new",
            query: query,
            body: [:],
            mutation: true,
        )
        do {
            return try parseAlias(json)
        } catch {
            throw AliasError.OutcomeUnknown
        }
    }

    func list(request value: ListAliasesRequest) async throws -> AliasPage {
        let page = try parsePageToken(value.pageToken)
        let json = try await request(
            method: "GET",
            path: "api/v2/aliases",
            query: [URLQueryItem(name: "page_id", value: String(page))],
        )
        guard let object = json as? [String: Any], let values = object["aliases"] as? [Any] else {
            throw AliasError.InvalidResponse
        }
        let aliases = try values.map(parseAlias)
        guard Set(aliases.map(\.identity.aliasId)).count == aliases.count else {
            throw AliasError.InvalidResponse
        }
        return AliasPage(
            aliases: aliases,
            nextPageToken: aliases.count == Constants.pageSize ? makePageToken(page + 1) : nil,
        )
    }

    func get(identity: AliasIdentity) async throws -> BitwardenSdk.Alias {
        let id = try providerAliasId(identity)
        let alias = try await parseAlias(request(method: "GET", path: "api/aliases/\(id)"))
        guard alias.identity.aliasId == id else { throw AliasError.InvalidResponse }
        return alias
    }

    func setEnabled(identity: AliasIdentity, enabled: Bool) async throws -> BitwardenSdk.Alias {
        let id = try providerAliasId(identity)
        var alias = try await get(identity: identity)
        var dispatched = false
        for _ in 0 ..< Constants.toggleAttemptLimit where (alias.lifecycle == .enabled) != enabled {
            do {
                _ = try await request(method: "POST", path: "api/aliases/\(id)/toggle", mutation: true)
                dispatched = true
                alias = try await get(identity: identity)
            } catch {
                if dispatched { throw AliasError.OutcomeUnknown }
                throw error
            }
        }
        guard (alias.lifecycle == .enabled) == enabled else { throw AliasError.SyncConflict }
        return alias
    }

    func delete(identity: AliasIdentity) async throws -> DeleteAliasResult {
        let id = try providerAliasId(identity)
        do {
            let json = try await request(method: "DELETE", path: "api/aliases/\(id)", mutation: true)
            guard let object = json as? [String: Any], object["deleted"] as? Bool == true else {
                throw AliasError.OutcomeUnknown
            }
        } catch let error as AliasError where error == .NotFound {
            // Deletion is idempotent for a provider-confirmed absent resource.
        }
        return DeleteAliasResult(identity: identity, deleted: true)
    }

    func createSendReplyIdentity(request value: CreateSendReplyIdentityRequest) async throws -> SendReplyIdentity {
        let id = try providerAliasId(value.alias)
        let json = try await request(
            method: "POST",
            path: "api/aliases/\(id)/contacts",
            body: ["contact": value.recipient],
            mutation: true,
        )
        do {
            return try parseSendReplyIdentity(json, alias: value.alias)
        } catch {
            throw AliasError.OutcomeUnknown
        }
    }

    func listSendReplyIdentities(alias: AliasIdentity, pageToken: String?) async throws -> SendReplyIdentityPage {
        let id = try providerAliasId(alias)
        let page = try parsePageToken(pageToken)
        let json = try await request(
            method: "GET",
            path: "api/aliases/\(id)/contacts",
            query: [URLQueryItem(name: "page_id", value: String(page))],
        )
        guard let object = json as? [String: Any], let values = object["contacts"] as? [Any] else {
            throw AliasError.InvalidResponse
        }
        let identities = try values.map { try parseSendReplyIdentity($0, alias: alias) }
        guard Set(identities.map(\.identityId)).count == identities.count else {
            throw AliasError.InvalidResponse
        }
        return SendReplyIdentityPage(
            identities: identities,
            nextPageToken: identities.count == Constants.pageSize ? makePageToken(page + 1) : nil,
        )
    }

    func removeSendReplyIdentity(identity: SendReplyIdentity) async throws {
        try validate(identity.alias)
        let id = try positiveIntegerString(identity.identityId)
        do {
            let json = try await request(method: "DELETE", path: "api/contacts/\(id)", mutation: true)
            guard let object = json as? [String: Any], object["deleted"] as? Bool == true else {
                throw AliasError.OutcomeUnknown
            }
        } catch let error as AliasError where error == .NotFound {
            // Removal is idempotent for a provider-confirmed absent identity.
        }
    }

    func setSendReplyBlocked(identity: SendReplyIdentity, blocked: Bool) async throws -> SendReplyIdentity {
        try validate(identity.alias)
        let id = try positiveIntegerString(identity.identityId)
        var current = try await findSendReplyIdentity(alias: identity.alias, identityId: id)
        var dispatched = false
        for _ in 0 ..< Constants.toggleAttemptLimit where current.blocked != blocked {
            do {
                _ = try await request(method: "POST", path: "api/contacts/\(id)/toggle", mutation: true)
                dispatched = true
                current = try await findSendReplyIdentity(alias: identity.alias, identityId: id)
            } catch {
                if dispatched { throw AliasError.OutcomeUnknown }
                throw error
            }
        }
        guard current.blocked == blocked else { throw AliasError.SyncConflict }
        return current
    }
}

private extension SimpleLoginAliasAdapter {
    private func findSendReplyIdentity(
        alias: AliasIdentity,
        identityId: String,
    ) async throws -> SendReplyIdentity {
        var token: String?
        for _ in 0 ..< Constants.contactLookupPageLimit {
            let page = try await listSendReplyIdentities(alias: alias, pageToken: token)
            if let match = page.identities.first(where: { $0.identityId == identityId }) { return match }
            guard let next = page.nextPageToken else { break }
            token = next
        }
        throw AliasError.NotFound
    }

    private func parseAlias(_ value: Any) throws -> BitwardenSdk.Alias {
        guard let object = value as? [String: Any],
              let rawId = object["id"] as? Int,
              rawId > 0,
              let rawAddress = object["email"] as? String,
              let enabled = object["enabled"] as? Bool
        else { throw AliasError.InvalidResponse }
        let address = try normalizedEmail(rawAddress)
        let identity = AliasIdentity(
            version: UInt32(AliasConnectionSchema.version),
            connectionId: connection.connectionId,
            aliasId: String(rawId),
            address: address,
        )
        return BitwardenSdk.Alias(
            identity: identity,
            lifecycle: enabled ? .enabled : .disabled,
            freshness: .current,
            consistency: .clean,
            label: nil,
            capabilities: Self.capabilities,
        )
    }

    private func parseSendReplyIdentity(_ value: Any, alias: AliasIdentity) throws -> SendReplyIdentity {
        try validate(alias)
        guard let object = value as? [String: Any],
              let rawId = object["id"] as? Int,
              rawId > 0,
              let recipient = object["contact"] as? String,
              let address = object["reverse_alias_address"] as? String,
              let blocked = object["block_forward"] as? Bool
        else { throw AliasError.InvalidResponse }
        return try SendReplyIdentity(
            alias: alias,
            identityId: String(rawId),
            recipient: normalizedEmail(recipient),
            address: normalizedEmail(address),
            valid: true,
            blocked: blocked,
        )
    }

    private func providerAliasId(_ identity: AliasIdentity) throws -> String {
        try validate(identity)
        return try positiveIntegerString(identity.aliasId)
    }

    private func validate(_ identity: AliasIdentity) throws {
        guard identity.version == UInt32(AliasConnectionSchema.version),
              identity.connectionId == connection.connectionId
        else { throw AliasError.PermissionDenied }
    }

    private func positiveIntegerString(_ value: String) throws -> String {
        guard !value.isEmpty,
              value.first != "0",
              value.allSatisfy(\.isNumber),
              UInt64(value) != nil
        else { throw AliasError.InvalidInput }
        return value
    }

    private func normalizedEmail(_ value: String) throws -> String {
        let address = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let parts = address.split(separator: "@", omittingEmptySubsequences: false)
        guard address.count <= 320,
              parts.count == 2,
              !parts[0].isEmpty,
              !parts[1].isEmpty,
              !address.contains(where: { $0.isWhitespace || $0 == "<" || $0 == ">" })
        else { throw AliasError.InvalidResponse }
        return address
    }

    private func parsePageToken(_ value: String?) throws -> Int {
        guard let value else { return 0 }
        let prefix = "simplelogin-page:"
        guard value.hasPrefix(prefix),
              let page = Int(value.dropFirst(prefix.count)),
              page >= 0
        else { throw AliasError.InvalidInput }
        return page
    }

    private func makePageToken(_ page: Int) -> String { "simplelogin-page:\(page)" }

    private func request(
        method: String,
        path: String,
        query: [URLQueryItem] = [],
        body: [String: Any]? = nil,
        mutation: Bool = false,
    ) async throws -> Any {
        try await transport.json(
            endpoint: baseUrl,
            method: method,
            path: path,
            query: query,
            headers: ["Authentication": token],
            body: body,
            mutation: mutation,
        )
    }
}

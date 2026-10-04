import BitwardenSdk
import Foundation
import XCTest

@testable import BitwardenShared

final class SimpleLoginAliasAdapterTests: BitwardenTestCase {
    private let connectionId = "11111111-1111-4111-8111-111111111111"

    override func tearDown() {
        AliasTestURLProtocol.handler = nil
        super.tearDown()
    }

    /// Exercises the shipped SDK artifact, its UniFFI callback seam, and the concrete provider
    /// adapter for create, read, enable/disable, and delete without external credentials.
    func test_aliasClient_crossesConcreteLifecycleAdapterBoundary() async throws {
        let provider = AliasProviderTestState()
        AliasTestURLProtocol.handler = provider.response
        let client = try makeClient()

        let created = try await client.create(request: CreateAliasRequest(hostname: "example.com"))
        XCTAssertEqual(client.connection().connectionId, connectionId)
        XCTAssertEqual(created.identity.aliasId, "42")
        XCTAssertEqual(created.identity.address, "alias@example.com")
        XCTAssertEqual(created.lifecycle, .enabled)

        let page = try await client.list(request: ListAliasesRequest(pageToken: nil))
        XCTAssertEqual(page.aliases, [created])
        XCTAssertNil(page.nextPageToken)

        let disabled = try await client.setEnabled(identity: created.identity, enabled: false)
        XCTAssertEqual(disabled.lifecycle, .disabled)

        let deletion = try await client.delete(identity: created.identity)
        XCTAssertTrue(deletion.deleted)
        XCTAssertEqual(deletion.identity, created.identity)

        let requests = provider.recordedRequests()
        XCTAssertEqual(requests.first?.value(forHTTPHeaderField: "Authentication"), "provider-token")
        XCTAssertEqual(requests.first?.url?.query, "hostname=example.com")
        XCTAssertTrue(requests.contains { $0.httpMethod == "POST" && $0.url?.path.hasSuffix("/toggle") == true })
        XCTAssertTrue(requests.contains { $0.httpMethod == "DELETE" && $0.url?.path == "/api/aliases/42" })
    }

    /// Send/reply identities and the negotiated block extension cross the same canonical callback
    /// seam; provider identifiers and payloads remain in the adapter.
    func test_aliasClient_crossesConcreteSendReplyAdapterBoundary() async throws {
        let provider = AliasProviderTestState()
        AliasTestURLProtocol.handler = provider.response
        let client = try makeClient()
        let alias = provider.aliasIdentity(connectionId: connectionId)

        let created = try await client.createSendReplyIdentity(request: CreateSendReplyIdentityRequest(
            alias: alias,
            recipient: "recipient@example.com",
        ))
        XCTAssertEqual(created.identityId, "91")
        XCTAssertEqual(created.address, "reply@example.com")
        XCTAssertEqual(created.blocked, false)

        let page = try await client.listSendReplyIdentities(alias: alias, pageToken: nil)
        XCTAssertEqual(page.identities, [created])

        let blocked = try await client.setSendReplyBlocked(identity: created, blocked: true)
        XCTAssertEqual(blocked.blocked, true)
        try await client.removeSendReplyIdentity(identity: blocked)

        let requests = provider.recordedRequests()
        XCTAssertTrue(requests.contains { $0.httpMethod == "POST" && $0.url?.path == "/api/aliases/42/contacts" })
        XCTAssertTrue(requests.contains { $0.httpMethod == "POST" && $0.url?.path == "/api/contacts/91/toggle" })
        XCTAssertTrue(requests.contains { $0.httpMethod == "DELETE" && $0.url?.path == "/api/contacts/91" })
    }

    /// A malformed mutation acknowledgement is unknowable, never treated as a safe retry.
    func test_create_invalidMutationResponseFailsOutcomeUnknown() async throws {
        AliasTestURLProtocol.handler = { _ in .json(["unexpected": true]) }
        let client = try makeClient()

        do {
            _ = try await client.create(request: CreateAliasRequest(hostname: nil))
            XCTFail("Malformed mutation response was accepted")
        } catch {
            XCTAssertEqual(error as? AliasError, .OutcomeUnknown)
        }
    }

    /// A server may apply a mutation before returning 5xx; it is not a safe retry signal.
    func test_create_serverFailureKeepsOutcomeUnknown() async throws {
        AliasTestURLProtocol.handler = { _ in .json([:], statusCode: 503) }
        let client = try makeClient()

        do {
            _ = try await client.create(request: CreateAliasRequest(hostname: nil))
            XCTFail("Server failure was accepted")
        } catch {
            XCTAssertEqual(error as? AliasError, .OutcomeUnknown)
        }
    }

    /// Read failures retain the ordinary availability error and never imply a mutation.
    func test_list_serverFailureReportsServiceUnavailable() async throws {
        AliasTestURLProtocol.handler = { _ in .json([:], statusCode: 503) }
        let client = try makeClient()

        do {
            _ = try await client.list(request: ListAliasesRequest(pageToken: nil))
            XCTFail("Server failure was accepted")
        } catch {
            XCTAssertEqual(error as? AliasError, .ServiceUnavailable)
        }
    }

    /// An echoed recipient mismatch is an uncertain mutation, even across SDK output validation.
    func test_createContact_recipientMismatchKeepsOutcomeUnknown() async throws {
        let provider = AliasProviderTestState()
        AliasTestURLProtocol.handler = { _ in
            .json([
                "id": 91,
                "contact": "other@example.com",
                "reverse_alias_address": "reply@example.com",
                "block_forward": false,
            ])
        }
        let client = try makeClient()

        do {
            _ = try await client.createSendReplyIdentity(request: CreateSendReplyIdentityRequest(
                alias: provider.aliasIdentity(connectionId: connectionId), recipient: "recipient@example.com",
            ))
            XCTFail("Mismatched recipient was accepted")
        } catch {
            XCTAssertEqual(error as? AliasError, .OutcomeUnknown)
        }
    }

    /// Control characters must fail in the adapter before a successful mutation reaches the SDK.
    func test_create_controlCharacterAddressKeepsOutcomeUnknown() async throws {
        AliasTestURLProtocol.handler = { _ in
            .json(["id": 42, "email": "alias\u{0001}@example.com", "enabled": true])
        }
        let client = try makeClient()

        do {
            _ = try await client.create(request: CreateAliasRequest(hostname: nil))
            XCTFail("Control-character address was accepted")
        } catch {
            XCTAssertEqual(error as? AliasError, .OutcomeUnknown)
        }
    }

    /// Plain HTTP credentials cannot be dispatched to a hostname disguised as a loopback address.
    func test_init_rejectsNonLoopbackHTTPBeforeNetworkRequest() throws {
        let provider = AliasProviderTestState()
        AliasTestURLProtocol.handler = provider.response

        XCTAssertThrowsError(try SimpleLoginAliasAdapter(
            connection: SimpleLoginAliasAdapter.makeConnection(connectionId: connectionId),
            credential: AliasConnectionCredential(
                token: "provider-token", baseUrl: "http://127.0.0.1.attacker.example/",
            ),
        )) { error in
            XCTAssertEqual(error as? AliasError, .InvalidInput)
        }
        XCTAssertTrue(provider.recordedRequests().isEmpty)
    }

    private func makeClient() throws -> AliasClient {
        let connection = SimpleLoginAliasAdapter.makeConnection(connectionId: connectionId)
        let credential = AliasConnectionCredential(
            token: "provider-token",
            baseUrl: "https://app.simplelogin.io/",
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AliasTestURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let adapter = try SimpleLoginAliasAdapter(
            connection: connection,
            credential: credential,
            session: session,
        )
        return try AliasClient(adapter: adapter)
    }
}

final class AliasProviderTestState: @unchecked Sendable {
    private let lock = NSLock()
    private var blocked = false
    private var enabled = true
    private var requests = [URLRequest]()

    func aliasIdentity(connectionId: String) -> AliasIdentity {
        AliasIdentity(
            version: UInt32(AliasConnectionSchema.version),
            connectionId: connectionId,
            aliasId: "42",
            address: "alias@example.com",
        )
    }

    func record(_ request: URLRequest) {
        lock.lock()
        requests.append(request)
        lock.unlock()
    }

    func recordedRequests() -> [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return requests
    }

    func response(_ request: URLRequest) throws -> AliasTestURLProtocol.Response {
        lock.lock()
        defer { lock.unlock() }
        requests.append(request)
        guard let path = request.url?.path else { return .json([:], statusCode: 400) }
        switch (request.httpMethod, path) {
        case ("POST", "/api/alias/random/new"):
            return .json(aliasPayload())
        case ("GET", "/api/v2/aliases"):
            return .json(["aliases": [aliasPayload()]])
        case ("GET", "/api/aliases/42"):
            return .json(aliasPayload())
        case ("POST", "/api/aliases/42/toggle"):
            enabled.toggle()
            return .json(["ok": true])
        case ("DELETE", "/api/aliases/42"):
            return .json(["deleted": true])
        case ("POST", "/api/aliases/42/contacts"):
            return .json(contactPayload())
        case ("GET", "/api/aliases/42/contacts"):
            return .json(["contacts": [contactPayload()]])
        case ("POST", "/api/contacts/91/toggle"):
            blocked.toggle()
            return .json(["ok": true])
        case ("DELETE", "/api/contacts/91"):
            return .json(["deleted": true])
        default:
            return .json([:], statusCode: 404)
        }
    }

    private func aliasPayload() -> [String: Any] {
        ["id": 42, "email": "Alias@Example.com", "enabled": enabled]
    }

    private func contactPayload() -> [String: Any] {
        [
            "id": 91,
            "contact": "Recipient@Example.com",
            "reverse_alias_address": "Reply@Example.com",
            "block_forward": blocked,
        ]
    }
}

final class AliasTestURLProtocol: URLProtocol, @unchecked Sendable {
    struct Response: @unchecked Sendable {
        let body: Any
        let statusCode: Int

        static func json(_ body: Any, statusCode: Int = 200) -> Response {
            Response(body: body, statusCode: statusCode)
        }
    }

    nonisolated(unsafe) static var handler: (@Sendable (URLRequest) throws -> Response)?

    static func jsonBody(_ request: URLRequest) throws -> [String: Any] {
        if let data = request.httpBody {
            return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        }
        let stream = try XCTUnwrap(request.httpBodyStream)
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 1024)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            guard count > 0 else { break }
            data.append(contentsOf: buffer.prefix(count))
        }
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    // swiftlint:disable:next static_over_final_class
    override class func canInit(with _: URLRequest) -> Bool { true }

    // swiftlint:disable:next static_over_final_class
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        do {
            let stub = try handler(request)
            guard let url = request.url,
                  let response = HTTPURLResponse(
                      url: url,
                      statusCode: stub.statusCode,
                      httpVersion: "HTTP/1.1",
                      headerFields: ["Content-Type": "application/json"],
                  )
            else { throw URLError(.badServerResponse) }
            let data = try JSONSerialization.data(withJSONObject: stub.body, options: [.sortedKeys])
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

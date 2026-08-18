import BitwardenKitMocks
import BitwardenSdk
import XCTest

@testable import BitwardenShared
@testable import BitwardenSharedMocks

final class EmailAliasServiceTests: BitwardenTestCase {
    private let connectionId = "11111111-1111-4111-8111-111111111111"
    private var cipherService: MockCipherService!
    private var clientService: MockClientService!
    private var fakeClient: FakeAliasClient!
    private var stateService: MockStateService!
    private var subject: DefaultEmailAliasService!
    private var syncService: MockSyncService!
    private var vaultTimeoutService: MockVaultTimeoutService!

    override func setUp() {
        super.setUp()
        cipherService = MockCipherService()
        clientService = MockClientService()
        fakeClient = FakeAliasClient(connectionId: connectionId)
        stateService = MockStateService()
        stateService.activeAccount = .fixture(profile: .fixture(userId: "account-1"))
        syncService = MockSyncService()
        vaultTimeoutService = MockVaultTimeoutService()
        subject = DefaultEmailAliasService(
            adapter: AliasAdapterRegistration(
                adapterId: SimpleLoginAliasAdapter.adapterId,
                defaultBaseUrl: ForwardedEmailServiceType.defaultSimpleLoginBaseUrl,
                makeConnection: SimpleLoginAliasAdapter.makeConnection,
                makeClient: { [fakeClient] _, _ in fakeClient! },
            ),
            cipherService: cipherService,
            clientService: clientService,
            stateService: stateService,
            syncService: syncService,
            vaultTimeoutService: vaultTimeoutService,
        )
    }

    override func tearDown() {
        cipherService = nil
        clientService = nil
        fakeClient = nil
        stateService = nil
        subject = nil
        syncService = nil
        vaultTimeoutService = nil
        super.tearDown()
    }

    /// Reading local state for view presentation never constructs or contacts the provider client.
    func test_loadProfile_doesNotContactProvider() async throws {
        let profile = try await subject.loadProfile(baseUrl: "https://app.simplelogin.io/")
        XCTAssertNil(profile)
        XCTAssertEqual(fakeClient.providerCallCount, 0)
    }

    /// One explicit create persists prepared and dispatched facts before exactly one callback.
    func test_createAlias_explicitActionPersistsDispatchAndCallsProviderOnce() async throws {
        cipherService.fetchAllCiphersResult = try .success([Cipher(cipherView: carrier())])

        let result = try await subject.createAlias(
            token: "encrypted-provider-token",
            baseUrl: "https://app.simplelogin.io/",
            hostname: "EXAMPLE.com",
        )

        XCTAssertEqual(fakeClient.createCallCount, 1)
        XCTAssertEqual(fakeClient.lastCreateRequest?.hostname, "example.com")
        XCTAssertEqual(fakeClient.providerCallCount, 1)
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 3)
        XCTAssertEqual(result.address, "alias@example.com")
        XCTAssertEqual(result.status, .enabled)
        let reference = try parseAliasReference(value: result.reference)
        XCTAssertEqual(reference.connectionId, connectionId)
        XCTAssertEqual(reference.aliasId, "42")
    }

    /// If encrypted dispatch cannot be persisted, an observed unbound alias is reused without a callback.
    func test_createAlias_offlineBeforeDispatchNeverContactsProvider() async throws {
        cipherService.fetchAllCiphersResult = try .success([Cipher(cipherView: carrier(observedAlias: true))])
        cipherService.addCipherWithServerResult = .failure(OfflineError())

        let result = try await subject.createAlias(
            token: "encrypted-provider-token",
            baseUrl: "https://app.simplelogin.io/",
            hostname: "example.com",
        )

        XCTAssertEqual(fakeClient.providerCallCount, 0)
        XCTAssertEqual(result.address, "alias@example.com")
        XCTAssertEqual(result.status, .enabled)
    }

    /// A persisted dispatch without a terminal fact remains unknown after a process restart.
    func test_loadProfile_dispatchedCreateWithoutTerminalEventIsUnknown() async throws {
        var payload = try carrierPayload(observedAlias: true)
        let operationId = "33333333-3333-4333-8333-333333333333"
        _ = try payload.journal.append(
            replicaId: "22222222-2222-4222-8222-222222222222",
            operationId: operationId,
            operation: .create,
            phase: .prepared,
        )
        _ = try payload.journal.append(
            replicaId: "22222222-2222-4222-8222-222222222222",
            operationId: operationId,
            operation: .create,
            phase: .dispatched,
        )
        cipherService.fetchAllCiphersResult = try .success([
            Cipher(cipherView: AliasConnectionVaultCodec.encode(payload)),
        ])

        let profile = try await subject.loadProfile(baseUrl: "https://app.simplelogin.io/")

        XCTAssertEqual(profile?.cachedAlias?.status, .unknown)
        XCTAssertEqual(fakeClient.providerCallCount, 0)
    }

    /// A callback arriving after extension/process expiry cannot publish decrypted state.
    func test_createAlias_lateCallbackAfterCancellationIsDiscarded() async throws {
        cipherService.fetchAllCiphersResult = try .success([Cipher(cipherView: carrier())])
        let providerStarted = expectation(description: "provider started")
        let gate = AliasCallGate()
        fakeClient.createHandler = { [fakeClient] in
            providerStarted.fulfill()
            await gate.wait()
            return fakeClient!.aliasFixture()
        }
        let operation = Task {
            try await self.subject.createAlias(
                token: "encrypted-provider-token",
                baseUrl: "https://app.simplelogin.io/",
                hostname: "example.com",
            )
        }
        await fulfillment(of: [providerStarted], timeout: 1)

        await subject.cancelAndClear()
        await gate.resume()

        do {
            _ = try await operation.value
            XCTFail("The cancelled operation returned a provider result")
        } catch {
            XCTAssertTrue(error is CancellationError)
        }
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 2)
    }

    /// Locking the vault while a callback is in flight rejects the callback before acknowledgement.
    func test_createAlias_lockRejectsLateCallback() async throws {
        cipherService.fetchAllCiphersResult = try .success([Cipher(cipherView: carrier())])
        let providerStarted = expectation(description: "provider started")
        let gate = AliasCallGate()
        fakeClient.createHandler = { [fakeClient] in
            providerStarted.fulfill()
            await gate.wait()
            return fakeClient!.aliasFixture()
        }
        let operation = Task {
            try await self.subject.createAlias(
                token: "encrypted-provider-token",
                baseUrl: "https://app.simplelogin.io/",
                hostname: "example.com",
            )
        }
        await fulfillment(of: [providerStarted], timeout: 1)

        await MainActor.run { vaultTimeoutService.isClientLocked["account-1"] = true }
        await gate.resume()

        do {
            _ = try await operation.value
            XCTFail("The locked operation returned a provider result")
        } catch {
            XCTAssertEqual(error as? EmailAliasError, .locked)
        }
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 2)
    }

    /// Switching accounts while a callback is in flight rejects the old account's result.
    func test_createAlias_accountSwitchRejectsLateCallback() async throws {
        cipherService.fetchAllCiphersResult = try .success([Cipher(cipherView: carrier())])
        let providerStarted = expectation(description: "provider started")
        let gate = AliasCallGate()
        fakeClient.createHandler = { [fakeClient] in
            providerStarted.fulfill()
            await gate.wait()
            return fakeClient!.aliasFixture()
        }
        let operation = Task {
            try await self.subject.createAlias(
                token: "encrypted-provider-token",
                baseUrl: "https://app.simplelogin.io/",
                hostname: "example.com",
            )
        }
        await fulfillment(of: [providerStarted], timeout: 1)

        stateService.activeAccount = .fixture(profile: .fixture(userId: "account-2"))
        await gate.resume()

        do {
            _ = try await operation.value
            XCTFail("The old account operation returned a provider result")
        } catch {
            XCTAssertEqual(error as? EmailAliasError, .accountChanged)
        }
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 2)
    }

    /// Disabling persists prepared, dispatched, and acknowledged lifecycle facts.
    func test_setAliasEnabled_explicitActionPersistsLifecycle() async throws {
        cipherService.fetchAllCiphersResult = try .success([Cipher(cipherView: carrier(observedAlias: true))])

        let result = try await subject.setAliasEnabled(aliasResult(), enabled: false)

        XCTAssertEqual(result.status, .disabled)
        XCTAssertEqual(fakeClient.setEnabledCallCount, 1)
        XCTAssertEqual(fakeClient.providerCallCount, 1)
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 3)
    }

    /// Deletion records a terminal tombstone without clearing the caller's valid login state.
    func test_deleteAlias_explicitActionPersistsTombstone() async throws {
        cipherService.fetchAllCiphersResult = try .success([Cipher(cipherView: carrier(observedAlias: true))])

        let result = try await subject.deleteAlias(aliasResult())

        XCTAssertEqual(result.status, .deleted)
        XCTAssertEqual(fakeClient.deleteCallCount, 1)
        XCTAssertEqual(fakeClient.providerCallCount, 1)
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 3)
    }

    /// Explicit reconciliation syncs first, consumes opaque pages, observes resources, and converges.
    func test_reconcile_explicitActionObservesProviderState() async throws {
        cipherService.fetchAllCiphersResult = try .success([Cipher(cipherView: carrier())])

        let result = try await subject.reconcile(baseUrl: "https://app.simplelogin.io/")

        XCTAssertEqual(result?.address, "alias@example.com")
        XCTAssertEqual(fakeClient.listCallCount, 2)
        XCTAssertEqual(fakeClient.providerCallCount, 2)
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 4)
    }

    private func aliasResult() throws -> EmailAliasResult {
        let identity = fakeClient.aliasFixture().identity
        return try EmailAliasResult(
            address: identity.address,
            reference: createAliasReference(identity: identity),
            identity: identity,
            status: .enabled,
        )
    }

    private func carrier(observedAlias: Bool = false) throws -> CipherView {
        try AliasConnectionVaultCodec.encode(carrierPayload(observedAlias: observedAlias))
    }

    private func carrierPayload(observedAlias: Bool = false) throws -> AliasConnectionVaultPayload {
        let connection = SimpleLoginAliasAdapter.makeConnection(connectionId: connectionId)
        var journal = try AliasJournal.empty(connectionId: connectionId)
        if observedAlias {
            let alias = fakeClient.aliasFixture()
            _ = try journal.append(
                replicaId: "22222222-2222-4222-8222-222222222222",
                operationId: "44444444-4444-4444-8444-444444444444",
                operation: .get,
                phase: .acknowledged,
                target: alias.identity,
                lifecycle: alias.lifecycle,
            )
        }
        return AliasConnectionVaultPayload(
            version: AliasConnectionSchema.version,
            connection: connection,
            credential: AliasConnectionCredential(
                token: "encrypted-provider-token",
                baseUrl: "https://app.simplelogin.io/",
            ),
            journal: journal,
        )
    }
}

private struct OfflineError: Error, Equatable {}

private final class FakeAliasClient: AliasClient, @unchecked Sendable {
    let testConnection: AliasConnection
    var createCallCount = 0
    var createHandler: (@Sendable () async throws -> BitwardenSdk.Alias)?
    var deleteCallCount = 0
    var lastCreateRequest: CreateAliasRequest?
    var listCallCount = 0
    var providerCallCount = 0
    var setEnabledCallCount = 0

    init(connectionId: String) {
        testConnection = SimpleLoginAliasAdapter.makeConnection(connectionId: connectionId)
        super.init(noHandle: NoHandle())
    }

    required init(unsafeFromHandle handle: UInt64) {
        testConnection = SimpleLoginAliasAdapter.makeConnection(
            connectionId: "11111111-1111-4111-8111-111111111111",
        )
        super.init(unsafeFromHandle: handle)
    }

    override func connection() -> AliasConnection { testConnection }

    override func create(request: CreateAliasRequest) async throws -> BitwardenSdk.Alias {
        createCallCount += 1
        providerCallCount += 1
        lastCreateRequest = request
        if let createHandler { return try await createHandler() }
        return aliasFixture()
    }

    override func delete(identity: AliasIdentity) async throws -> DeleteAliasResult {
        deleteCallCount += 1
        providerCallCount += 1
        return DeleteAliasResult(identity: identity, deleted: true)
    }

    override func list(request: ListAliasesRequest) async throws -> AliasPage {
        listCallCount += 1
        providerCallCount += 1
        if request.pageToken == nil {
            return AliasPage(aliases: [aliasFixture()], nextPageToken: "page-1")
        }
        return AliasPage(aliases: [], nextPageToken: nil)
    }

    override func setEnabled(identity _: AliasIdentity, enabled: Bool) async throws -> BitwardenSdk.Alias {
        setEnabledCallCount += 1
        providerCallCount += 1
        return aliasFixture(lifecycle: enabled ? .enabled : .disabled)
    }

    func aliasFixture(lifecycle: AliasLifecycleState = .enabled) -> BitwardenSdk.Alias {
        BitwardenSdk.Alias(
            identity: AliasIdentity(
                version: 1,
                connectionId: testConnection.connectionId,
                aliasId: "42",
                address: "alias@example.com",
            ),
            lifecycle: lifecycle,
            freshness: .current,
            consistency: .clean,
            label: nil,
            capabilities: SimpleLoginAliasAdapter.capabilities,
        )
    }
}

private actor AliasCallGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var resumed = false

    func wait() async {
        if resumed { return }
        await withCheckedContinuation { continuation = $0 }
    }

    func resume() {
        resumed = true
        continuation?.resume()
        continuation = nil
    }
}

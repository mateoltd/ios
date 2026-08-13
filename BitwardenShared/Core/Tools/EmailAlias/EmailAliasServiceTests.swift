import BitwardenKitMocks
import BitwardenSdk
import XCTest

@testable import BitwardenShared
@testable import BitwardenSharedMocks

// swiftlint:disable file_length
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
            cipherService: cipherService,
            clientService: clientService,
            stateService: stateService,
            syncService: syncService,
            vaultTimeoutService: vaultTimeoutService,
            clientFactory: { [fakeClient] _ in fakeClient! },
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

    /// One explicit create call persists dispatch before contacting the provider exactly once.
    func test_createAlias_explicitActionPersistsDispatchAndCallsProviderOnce() async throws {
        let carrier = try AliasConnectionVaultCodec.encode(carrierPayload())
        cipherService.fetchAllCiphersResult = .success([Cipher(cipherView: carrier)])

        let result = try await subject.createAlias(
            token: "encrypted-provider-token",
            baseUrl: "https://app.simplelogin.io/",
            hostname: "example.com",
        )

        XCTAssertEqual(fakeClient.createRandomAliasCallCount, 1)
        XCTAssertEqual(fakeClient.providerCallCount, 2)
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 3)
        XCTAssertEqual(result.address, "alias@example.com")
        XCTAssertEqual(result.status, .enabled)
        let reference = try parseAliasReference(value: result.reference)
        XCTAssertEqual(reference.connectionId, connectionId)
        XCTAssertEqual(reference.aliasId, 42)
    }

    /// If encrypted dispatch cannot be persisted, an observed unbound alias is reused without a provider call.
    func test_createAlias_offlineBeforeDispatchNeverContactsProvider() async throws {
        let carrier = try AliasConnectionVaultCodec.encode(carrierPayload(observedAlias: true))
        cipherService.fetchAllCiphersResult = .success([Cipher(cipherView: carrier)])
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

    /// A persisted dispatch without a terminal event remains unknown after a process restart.
    func test_loadProfile_dispatchedCreateWithoutTerminalEventIsUnknown() async throws {
        var payload = try carrierPayload(observedAlias: true)
        let operation = try payload.sync.append(
            kind: "provider-operation",
            value: AliasProviderOperation(
                operation: "create",
                connection: payload.connection,
                request: AliasCreateIntent(kind: "random", hostname: nil, mode: nil, note: nil),
                alias: nil,
            ),
        )
        _ = try payload.sync.append(kind: "provider-dispatched", operationId: operation.id)
        let carrier = try AliasConnectionVaultCodec.encode(payload)
        cipherService.fetchAllCiphersResult = .success([Cipher(cipherView: carrier)])

        let profile = try await subject.loadProfile(baseUrl: "https://app.simplelogin.io/")

        XCTAssertEqual(profile?.cachedAlias?.status, .unknown)
        XCTAssertEqual(fakeClient.providerCallCount, 0)
    }

    /// A provider callback arriving after extension/process expiry cannot publish decrypted state.
    func test_createAlias_lateCallbackAfterCancellationIsDiscarded() async throws {
        let carrier = try AliasConnectionVaultCodec.encode(carrierPayload())
        cipherService.fetchAllCiphersResult = .success([Cipher(cipherView: carrier)])
        let providerStarted = expectation(description: "provider started")
        let gate = AliasCallGate()
        fakeClient.createRandomAliasHandler = { [fakeClient] in
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

    /// Locking the vault while the provider is in flight rejects the callback before acknowledgement.
    func test_createAlias_lockRejectsLateCallback() async throws {
        let carrier = try AliasConnectionVaultCodec.encode(carrierPayload())
        cipherService.fetchAllCiphersResult = .success([Cipher(cipherView: carrier)])
        let providerStarted = expectation(description: "provider started")
        let gate = AliasCallGate()
        fakeClient.createRandomAliasHandler = { [fakeClient] in
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

        await MainActor.run {
            vaultTimeoutService.isClientLocked["account-1"] = true
        }
        await gate.resume()

        do {
            _ = try await operation.value
            XCTFail("The locked operation returned a provider result")
        } catch {
            XCTAssertEqual(error as? EmailAliasError, .locked)
        }
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 2)
    }

    /// Switching accounts while the provider is in flight rejects the old account's callback.
    func test_createAlias_accountSwitchRejectsLateCallback() async throws {
        let carrier = try AliasConnectionVaultCodec.encode(carrierPayload())
        cipherService.fetchAllCiphersResult = .success([Cipher(cipherView: carrier)])
        let providerStarted = expectation(description: "provider started")
        let gate = AliasCallGate()
        fakeClient.createRandomAliasHandler = { [fakeClient] in
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

    /// Disabling an alias persists operation, dispatch, and acknowledgement around one provider call.
    func test_setAliasEnabled_explicitActionPersistsLifecycle() async throws {
        let carrier = try AliasConnectionVaultCodec.encode(carrierPayload(observedAlias: true))
        cipherService.fetchAllCiphersResult = .success([Cipher(cipherView: carrier)])

        let result = try await subject.setAliasEnabled(aliasResult(), enabled: false)

        XCTAssertEqual(result.status, .disabled)
        XCTAssertEqual(fakeClient.setAliasEnabledCallCount, 1)
        XCTAssertEqual(fakeClient.providerCallCount, 1)
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 3)
    }

    /// Deleting an alias records a terminal tombstone without clearing the caller's valid login state.
    func test_deleteAlias_explicitActionPersistsTombstone() async throws {
        let carrier = try AliasConnectionVaultCodec.encode(carrierPayload(observedAlias: true))
        cipherService.fetchAllCiphersResult = .success([Cipher(cipherView: carrier)])

        let result = try await subject.deleteAlias(aliasResult())

        XCTAssertEqual(result.status, .deleted)
        XCTAssertEqual(fakeClient.deleteAliasCallCount, 1)
        XCTAssertEqual(fakeClient.providerCallCount, 1)
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 3)
    }

    /// Reconciliation is explicit, syncs first, observes provider state, and returns the cached alias.
    func test_reconcile_explicitActionObservesProviderState() async throws {
        let carrier = try AliasConnectionVaultCodec.encode(carrierPayload())
        cipherService.fetchAllCiphersResult = .success([Cipher(cipherView: carrier)])

        let result = try await subject.reconcile(baseUrl: "https://app.simplelogin.io/")

        XCTAssertEqual(result?.address, "alias@example.com")
        XCTAssertEqual(fakeClient.listAliasesCallCount, 2)
        XCTAssertEqual(fakeClient.providerIdentityCallCount, 1)
        XCTAssertEqual(fakeClient.providerCallCount, 3)
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 1)
    }

    private func aliasResult() throws -> EmailAliasResult {
        let connection = AliasProviderConnection(
            providerInstance: "https://app.simplelogin.io/",
            connectionId: connectionId,
        )
        let alias = fakeClient.aliasFixture()
        let identity = EmailAliasIdentity(alias: alias, connection: connection)
        guard let reference = identity.sdkReference else {
            throw EmailAliasError.invalidEncryptedState
        }
        return try EmailAliasResult(
            address: identity.address,
            reference: serializeAliasReference(reference: reference),
            identity: identity,
            status: .enabled,
        )
    }

    private func carrierPayload(observedAlias: Bool = false) throws -> AliasConnectionVaultPayload {
        let connection = AliasProviderConnection(
            providerInstance: "https://app.simplelogin.io/",
            connectionId: connectionId,
        )
        var sync = AliasSyncDocument(replicaId: "22222222-2222-4222-8222-222222222222")
        _ = try sync.append(kind: "connection-upsert", connection: connection)
        if observedAlias {
            _ = try sync.append(
                kind: "provider-observe",
                snapshot: AliasProviderSnapshot(alias: fakeClient.aliasFixture(), connection: connection),
            )
        }
        return AliasConnectionVaultPayload(
            version: AliasConnectionSchema.version,
            connection: connection,
            credential: AliasConnectionCredential(
                token: "encrypted-provider-token",
                baseUrl: "https://app.simplelogin.io/",
            ),
            sync: sync,
        )
    }
}

private struct OfflineError: Error, Equatable {}

private final class FakeAliasClient: AliasClient, @unchecked Sendable {
    let connectionId: String
    var createRandomAliasCallCount = 0
    var createRandomAliasHandler: (@Sendable () async throws -> BitwardenSdk.Alias)?
    var deleteAliasCallCount = 0
    var listAliasesCallCount = 0
    var providerCallCount = 0
    var providerIdentityCallCount = 0
    var setAliasEnabledCallCount = 0

    init(connectionId: String) {
        self.connectionId = connectionId
        super.init(noHandle: NoHandle())
    }

    required init(unsafeFromHandle handle: UInt64) {
        connectionId = "11111111-1111-4111-8111-111111111111"
        super.init(unsafeFromHandle: handle)
    }

    override func createRandomAlias(request _: CreateRandomAliasRequest) async throws -> BitwardenSdk.Alias {
        createRandomAliasCallCount += 1
        providerCallCount += 1
        if let createRandomAliasHandler {
            return try await createRandomAliasHandler()
        }
        return aliasFixture()
    }

    func aliasFixture() -> BitwardenSdk.Alias {
        let mailbox = MailboxRef(id: 7, email: "mailbox@example.com")
        return BitwardenSdk.Alias(
            id: 42,
            email: "alias@example.com",
            creationDate: "2026-08-13T00:00:00Z",
            creationTimestamp: 1_786_579_200,
            enabled: true,
            note: nil,
            name: nil,
            nbForward: 0,
            nbBlock: 0,
            nbReply: 0,
            mailbox: mailbox,
            mailboxes: [mailbox],
            supportPgp: false,
            disablePgp: false,
            latestActivity: nil,
            pinned: false,
        )
    }

    override func createAliasReference(alias: BitwardenSdk.Alias) throws -> SensitiveString {
        providerCallCount += 1
        return try serializeAliasReference(reference: AliasReference(
            version: 1,
            provider: .simpleLogin,
            providerInstance: "https://app.simplelogin.io/",
            connectionId: connectionId,
            aliasId: alias.id,
            address: alias.email,
        ))
    }

    override func deleteAlias(aliasId: AliasId) async throws -> DeleteAliasResult {
        deleteAliasCallCount += 1
        providerCallCount += 1
        return DeleteAliasResult(id: aliasId, deleted: true)
    }

    override func listAliases(page: UInt32, filter _: AliasFilter?) async throws -> AliasPage {
        listAliasesCallCount += 1
        providerCallCount += 1
        return AliasPage(page: page, aliases: page == 0 ? [aliasFixture()] : [])
    }

    override func providerIdentity() throws -> AliasProviderIdentity {
        providerIdentityCallCount += 1
        providerCallCount += 1
        return AliasProviderIdentity(
            provider: .simpleLogin,
            instance: "https://app.simplelogin.io/",
            connectionId: connectionId,
        )
    }

    override func setAliasEnabled(aliasId: AliasId, enabled: Bool) async throws -> AliasState {
        setAliasEnabledCallCount += 1
        providerCallCount += 1
        return AliasState(id: aliasId, enabled: enabled)
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

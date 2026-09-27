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

    /// Carrier writes preserve the SDK's key identity so the server can reject stale-key writes.
    func test_createAlias_preservesEncryptionKeyId() async throws {
        cipherService.fetchAllCiphersResult = try .success([Cipher(cipherView: carrier())])
        clientService.mockVault.clientCiphers.encryptClosure = { view in
            EncryptionContext(
                encryptedFor: "account-1",
                encryptedByKeyId: "key-1",
                cipher: Cipher(cipherView: view),
            )
        }

        _ = try await subject.createAlias(
            token: "encrypted-provider-token",
            baseUrl: "https://app.simplelogin.io/",
            hostname: "example.com",
        )

        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 3)
        XCTAssertEqual(cipherService.addCipherWithServerEncryptedByKeyId, "key-1")
        XCTAssertEqual(cipherService.addCipherWithServerEncryptedFor, "account-1")
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

    /// An unreadable login cannot be treated as proof that a cached alias is unbound.
    func test_createAlias_offlineCacheReuseRequiresReadableBindings() async throws {
        cipherService.fetchAllCiphersResult = try .success([
            Cipher(cipherView: carrier(observedAlias: true)),
            .fixture(type: .login),
        ])
        cipherService.addCipherWithServerResult = .failure(OfflineError())
        clientService.mockVault.clientCiphers.decryptClosure = { cipher in
            guard cipher.type != .login else { throw OfflineError() }
            return CipherView(cipher: cipher)
        }

        do {
            _ = try await subject.createAlias(
                token: "encrypted-provider-token",
                baseUrl: "https://app.simplelogin.io/",
                hostname: "example.com",
            )
            XCTFail("An unreadable login allowed cached alias reuse")
        } catch {
            XCTAssertTrue(error is OfflineError)
        }
        XCTAssertEqual(fakeClient.providerCallCount, 0)
    }

    /// Cancelling the caller also cancels the actor's provider task.
    func test_createAlias_callerCancellationDiscardsLateCallback() async throws {
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

        operation.cancel()
        await gate.resume()

        do {
            _ = try await operation.value
            XCTFail("The cancelled caller received a provider result")
        } catch {
            XCTAssertTrue(error is CancellationError)
        }
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 2)
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

    /// A saved login can be managed even though generator reuse excludes it.
    func test_loadBoundAlias_resolvesSavedBindingWithoutProvider() async throws {
        let alias = try aliasResult()
        let login = CipherView.fixture(
            id: "saved-login", login: .fixture(aliasReference: alias.reference, username: alias.address),
        )
        cipherService.fetchAllCiphersResult = try .success([
            Cipher(cipherView: carrier(observedAlias: true)), Cipher(cipherView: login),
        ])
        let profile = try await subject.loadProfile(baseUrl: "https://app.simplelogin.io/")
        XCTAssertNil(profile?.cachedAlias)
        let result = try await subject.loadBoundAlias(BoundEmailAlias(
            cipherId: "saved-login", userId: "account-1", reference: alias.reference,
        ))
        XCTAssertEqual(result, alias)
        XCTAssertEqual(fakeClient.providerCallCount, 0)
    }

    /// A stale route cannot read another account, or a login whose username/binding changed.
    func test_loadBoundAlias_rejectsStaleOwnerAndBinding() async throws {
        let alias = try aliasResult()
        cipherService.fetchAllCiphersResult = try .success([
            Cipher(cipherView: carrier(observedAlias: true)),
            Cipher(cipherView: .fixture(
                id: "saved-login", login: .fixture(aliasReference: alias.reference, username: "changed@example.com"),
            )),
        ])
        for owner in ["account-2", "account-1"] {
            do {
                _ = try await subject.loadBoundAlias(BoundEmailAlias(
                    cipherId: "saved-login", userId: owner, reference: alias.reference,
                ))
                XCTFail("A stale route was accepted")
            } catch {
                XCTAssertEqual(error as? EmailAliasError, owner == "account-2" ? .accountChanged : .conflict)
            }
        }
        XCTAssertEqual(fakeClient.providerCallCount, 0)
    }

    func test_setAliasEnabled_rejectsResultFromOtherAccount() async throws {
        var alias = try aliasResult()
        alias.ownerUserId = "account-2"
        do {
            _ = try await subject.setAliasEnabled(alias, enabled: false)
            XCTFail("A stale result was accepted")
        } catch { XCTAssertEqual(error as? EmailAliasError, .accountChanged) }
        XCTAssertEqual(fakeClient.providerCallCount, 0)
    }

    /// Sync delivers the connection root to a fresh local vault before provider-list recovery.
    func test_recovery_loadsConnectionFromSyncIntoFreshVault() async throws {
        let encryptedCarrier = try Cipher(cipherView: carrier(observedAlias: true))
        cipherService.fetchAllCiphersResult = .success([])
        let before = try await subject.loadProfile(baseUrl: "https://app.simplelogin.io/")
        XCTAssertNil(before)
        syncService.fetchSyncHandler = { [cipherService] in
            cipherService?.fetchAllCiphersResult = .success([encryptedCarrier])
        }
        let aliases = try await subject.recoverAliases(baseUrl: "https://app.simplelogin.io/")
        let recovered = try await subject.loadProfile(baseUrl: "https://app.simplelogin.io/")
        XCTAssertEqual(syncService.fetchSyncForceSync, true)
        XCTAssertEqual(recovered?.connectionId, connectionId)
        XCTAssertEqual(recovered?.token, "encrypted-provider-token")
        XCTAssertEqual(aliases.first?.identity.connectionId, connectionId)
        XCTAssertEqual(fakeClient.createCallCount, 0)
    }

    /// A new process recovers credentials/journal from encrypted sync carriers, not ordinary exports.
    func test_recovery_syncedCarrierPreservesUnknownCreateWithoutRepeatingIt() async throws {
        var payload = try carrierPayload()
        let operationId = UUID().uuidString.lowercased()
        for phase in [AliasOperationPhase.prepared, .dispatched] {
            _ = try payload.journal.append(
                replicaId: "22222222-2222-4222-8222-222222222222",
                operationId: operationId, operation: .create, phase: phase,
            )
        }
        cipherService.fetchAllCiphersResult = try .success([
            Cipher(cipherView: AliasConnectionVaultCodec.encode(payload)),
        ])
        let profile = try await subject.loadProfile(baseUrl: "https://app.simplelogin.io/")
        XCTAssertEqual(profile?.recoveryNeeded, true)
        XCTAssertEqual(profile?.token, "encrypted-provider-token")
        XCTAssertNil(profile?.cachedAlias)
        let aliases = try await subject.recoverAliases(baseUrl: "https://app.simplelogin.io/")
        XCTAssertEqual(syncService.fetchSyncForceSync, true)
        XCTAssertEqual(aliases.map(\.address), ["alias@example.com"])
        do {
            _ = try await subject.createAlias(
                token: "encrypted-provider-token", baseUrl: "https://app.simplelogin.io/", hostname: nil,
            )
            XCTFail("An uncertain create was repeated")
        } catch { XCTAssertEqual(error as? EmailAliasError, .operationOutcomeUnknown) }
        XCTAssertEqual(fakeClient.createCallCount, 0)
    }

    /// Read/list recovery never creates a duplicate reverse identity for the same recipient.
    func test_contacts_existingRecipientIsReusedWithoutMutation() async throws {
        cipherService.fetchAllCiphersResult = try .success([Cipher(cipherView: carrier(observedAlias: true))])
        fakeClient.contactIdentities = [fakeClient.contactFixture()]
        let contacts = try await subject.contacts(aliasResult(), operation: .create(recipient: "PERSON@example.com"))
        XCTAssertEqual(contacts, fakeClient.contactIdentities)
        XCTAssertEqual(fakeClient.contactCreateCallCount, 0)
        XCTAssertTrue(cipherService.addCipherWithServerCiphers.isEmpty)
    }

    /// An uncertain contact create is durable across restart; list still works, blind creation does not.
    func test_contacts_uncertainCreateAllowsListButRejectsAnotherCreate() async throws {
        var payload = try carrierPayload(observedAlias: true)
        let operationId = UUID().uuidString.lowercased()
        for phase in [AliasOperationPhase.prepared, .dispatched] {
            _ = try payload.journal.append(
                replicaId: "22222222-2222-4222-8222-222222222222", operationId: operationId,
                operation: .createSendReplyIdentity, phase: phase, target: fakeClient.aliasFixture().identity,
            )
        }
        cipherService.fetchAllCiphersResult = try .success([
            Cipher(cipherView: AliasConnectionVaultCodec.encode(payload)),
        ])
        let contacts = try await subject.contacts(aliasResult(), operation: .list)
        XCTAssertTrue(contacts.isEmpty)
        do {
            _ = try await subject.contacts(aliasResult(), operation: .create(recipient: "person@example.com"))
            XCTFail("A second identity was created")
        } catch { XCTAssertEqual(error as? EmailAliasError, .operationOutcomeUnknown) }
        XCTAssertEqual(fakeClient.contactCreateCallCount, 0)
    }

    func test_contacts_dispatchFailureDoesNotCreateIdentity() async throws {
        cipherService.fetchAllCiphersResult = try .success([Cipher(cipherView: carrier(observedAlias: true))])
        cipherService.addCipherWithServerResult = .failure(OfflineError())
        do {
            _ = try await subject.contacts(aliasResult(), operation: .create(recipient: "person@example.com"))
            XCTFail("Dispatch without durable encrypted state was accepted")
        } catch { XCTAssertEqual(error as? EmailAliasError, .conflict) }
        XCTAssertEqual(fakeClient.contactCreateCallCount, 0)
    }

    func test_refreshAlias_preservesIdentityAndPersistsObservation() async throws {
        cipherService.fetchAllCiphersResult = try .success([Cipher(cipherView: carrier(observedAlias: true))])
        let refreshed = try await subject.refreshAlias(aliasResult())
        XCTAssertEqual(refreshed, try aliasResult())
        XCTAssertEqual(fakeClient.getCallCount, 1)
        XCTAssertEqual(fakeClient.createCallCount, 0)
        XCTAssertEqual(cipherService.addCipherWithServerCiphers.count, 1)
    }

    private func aliasResult() throws -> EmailAliasResult {
        let identity = fakeClient.aliasFixture().identity
        return try EmailAliasResult(
            address: identity.address,
            reference: createAliasReference(identity: identity),
            identity: identity,
            status: .enabled,
            ownerUserId: "account-1",
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
    var contactCreateCallCount = 0
    var contactIdentities = [SendReplyIdentity]()
    var getCallCount = 0
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

    override func get(identity: AliasIdentity) async throws -> BitwardenSdk.Alias {
        getCallCount += 1
        providerCallCount += 1
        return aliasFixture()
    }

    override func listSendReplyIdentities(
        alias: AliasIdentity,
        pageToken: String?,
    ) async throws -> SendReplyIdentityPage {
        providerCallCount += 1
        return SendReplyIdentityPage(identities: contactIdentities, nextPageToken: nil)
    }

    override func createSendReplyIdentity(request: CreateSendReplyIdentityRequest) async throws -> SendReplyIdentity {
        contactCreateCallCount += 1
        providerCallCount += 1
        return contactFixture()
    }

    func contactFixture() -> SendReplyIdentity {
        SendReplyIdentity(
            alias: aliasFixture().identity, identityId: "7", recipient: "person@example.com",
            address: "reverse@example.com", valid: true, blocked: false,
        )
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

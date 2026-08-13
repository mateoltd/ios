@testable import BitwardenShared

final class MockEmailAliasService: EmailAliasService {
    var cancelAndClearCalled = false
    var createAliasCallCount = 0
    var createAliasResult: Result<EmailAliasResult, Error> = .failure(EmailAliasError.noCachedAlias)
    var deleteAliasResult: Result<EmailAliasResult, Error> = .failure(EmailAliasError.noCachedAlias)
    var loadProfileResult: Result<EmailAliasProfile?, Error> = .success(nil)
    var reconcileResult: Result<EmailAliasResult?, Error> = .success(nil)
    var setEnabledResult: Result<EmailAliasResult, Error> = .failure(EmailAliasError.noCachedAlias)

    private(set) var baseUrl: String?
    private(set) var enabled: Bool?
    private(set) var hostname: String?
    private(set) var token: String?

    func loadProfile(baseUrl: String) async throws -> EmailAliasProfile? {
        self.baseUrl = baseUrl
        return try loadProfileResult.get()
    }

    func createAlias(token: String, baseUrl: String, hostname: String?) async throws -> EmailAliasResult {
        createAliasCallCount += 1
        self.token = token
        self.baseUrl = baseUrl
        self.hostname = hostname
        return try createAliasResult.get()
    }

    func setAliasEnabled(_ alias: EmailAliasResult, enabled: Bool) async throws -> EmailAliasResult {
        self.enabled = enabled
        return try setEnabledResult.get()
    }

    func deleteAlias(_ alias: EmailAliasResult) async throws -> EmailAliasResult {
        try deleteAliasResult.get()
    }

    func reconcile(baseUrl: String) async throws -> EmailAliasResult? {
        self.baseUrl = baseUrl
        return try reconcileResult.get()
    }

    func cancelAndClear() async {
        cancelAndClearCalled = true
    }
}

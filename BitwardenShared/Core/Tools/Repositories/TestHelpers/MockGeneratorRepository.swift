import BitwardenSdk
import Combine

@testable import BitwardenShared

class MockGeneratorRepository: GeneratorRepository {
    var addPasswordHistoryCalled = false

    var clearPasswordHistoryCalled = false
    var clearPasswordHistoryResult: Result<Void, Error> = .success(())

    var passwordHistorySubject = CurrentValueSubject<[PasswordHistoryView], Error>([])

    var masterPasswordGeneratorCalled = false
    var masterPasswordGeneratorResult: Result<String, Error> = .success("MASTER_PASSWORD")

    var passphraseGeneratorRequest: PassphraseGeneratorRequest?
    var passphraseResult: Result<String, Error> = .success("PASSPHRASE")

    var passwordGeneratorRequest: PasswordGeneratorRequest?
    var passwordResult: Result<String, Error> = .success("PASSWORD")

    var passwordRulesRequestRules: String?
    var passwordRulesRequestResult: PasswordGeneratorRequest? = PasswordGeneratorRequest(
        lowercase: true,
        uppercase: true,
        numbers: true,
        special: false,
        length: 14,
        avoidAmbiguous: false,
        minLowercase: nil,
        minUppercase: nil,
        minNumber: nil,
        minSpecial: nil,
    )

    var usernameGeneratorRequest: AppUsernameGeneratorRequest?
    var usernameResult: Result<String, Error> = .success("USERNAME")

    var cancelEmailAliasOperationsCalled = false
    var createEmailAliasCallCount = 0
    var createEmailAliasHandler: ((String, String, String?) async throws -> EmailAliasResult)?
    var createEmailAliasResult: Result<EmailAliasResult, Error> = .failure(EmailAliasError.noCachedAlias)
    var deleteEmailAliasResult: Result<EmailAliasResult, Error> = .failure(EmailAliasError.noCachedAlias)
    var loadEmailAliasProfileHandler: ((String) async throws -> EmailAliasProfile?)?
    var loadEmailAliasProfileResult: Result<EmailAliasProfile?, Error> = .success(nil)
    var reconcileEmailAliasesResult: Result<EmailAliasResult?, Error> = .success(nil)
    var setEmailAliasEnabledResult: Result<EmailAliasResult, Error> = .failure(EmailAliasError.noCachedAlias)

    private(set) var emailAliasBaseUrl: String?
    private(set) var emailAliasEnabled: Bool?
    private(set) var emailAliasHostname: String?
    private(set) var emailAliasToken: String?

    // swiftlint:disable identifier_name
    var getEffectivePasswordGenerationOptionsCalled = false
    var getEffectivePasswordGenerationOptionsRules: String?
    var getEffectivePasswordGenerationOptionsIsPolicyInEffect = false
    // swiftlint:enable identifier_name

    var getPasswordGenerationOptionsCalled = false
    var getPasswordGenerationOptionsResult: Result<PasswordGenerationOptions, Error> =
        .success(PasswordGenerationOptions())
    var passwordGenerationOptions = PasswordGenerationOptions()
    var setPasswordGenerationOptionsResult: Result<Void, Error> = .success(())

    var getUsernameGenerationOptionsCalled = false
    var getUsernameGenerationOptionsResult: Result<UsernameGenerationOptions, Error> =
        .success(UsernameGenerationOptions())
    var usernameGenerationOptions = UsernameGenerationOptions()
    var setUsernameGenerationOptionsResult: Result<Void, Error> = .success(())

    var usernamePlusAddressEmail: String?
    var usernamePlusAddressEmailResult: Result<String, Error> = .success("user+abcd0123@bitwarden.com")

    // MARK: Password History

    func addPasswordHistory(_ passwordHistory: PasswordHistoryView) async throws {
        addPasswordHistoryCalled = true
        passwordHistorySubject.value.insert(passwordHistory, at: 0)
    }

    func clearPasswordHistory() async throws {
        clearPasswordHistoryCalled = true
        passwordHistorySubject.value.removeAll()
        try clearPasswordHistoryResult.get()
    }

    func passwordHistoryPublisher() -> AsyncThrowingPublisher<AnyPublisher<[PasswordHistoryView], Error>> {
        passwordHistorySubject.eraseToAnyPublisher().values
    }

    // MARK: Generator

    func generateMasterPassword() async throws -> String {
        masterPasswordGeneratorCalled = true
        return try masterPasswordGeneratorResult.get()
    }

    func generatePassphrase(settings: PassphraseGeneratorRequest, isPreAuth: Bool) async throws -> String {
        passphraseGeneratorRequest = settings
        return try passphraseResult.get()
    }

    func generatePassword(settings: PasswordGeneratorRequest) async throws -> String {
        passwordGeneratorRequest = settings
        return try passwordResult.get()
    }

    func generateUsername(settings: AppUsernameGeneratorRequest) async throws -> String {
        usernameGeneratorRequest = settings
        return try usernameResult.get()
    }

    func loadEmailAliasProfile(baseUrl: String) async throws -> EmailAliasProfile? {
        emailAliasBaseUrl = baseUrl
        if let loadEmailAliasProfileHandler {
            return try await loadEmailAliasProfileHandler(baseUrl)
        }
        return try loadEmailAliasProfileResult.get()
    }

    func createEmailAlias(token: String, baseUrl: String, hostname: String?) async throws -> EmailAliasResult {
        createEmailAliasCallCount += 1
        emailAliasToken = token
        emailAliasBaseUrl = baseUrl
        emailAliasHostname = hostname
        if let createEmailAliasHandler {
            return try await createEmailAliasHandler(token, baseUrl, hostname)
        }
        return try createEmailAliasResult.get()
    }

    func setEmailAliasEnabled(_ alias: EmailAliasResult, enabled: Bool) async throws -> EmailAliasResult {
        emailAliasEnabled = enabled
        return try setEmailAliasEnabledResult.get()
    }

    func deleteEmailAlias(_ alias: EmailAliasResult) async throws -> EmailAliasResult {
        try deleteEmailAliasResult.get()
    }

    func reconcileEmailAliases(baseUrl: String) async throws -> EmailAliasResult? {
        emailAliasBaseUrl = baseUrl
        return try reconcileEmailAliasesResult.get()
    }

    func cancelEmailAliasOperations() async {
        cancelEmailAliasOperationsCalled = true
    }

    func generateUsernamePlusAddressedEmail(email: String) async throws -> String {
        usernamePlusAddressEmail = email
        return try usernamePlusAddressEmailResult.get()
    }

    func getEffectivePasswordGenerationOptions(
        rules: String?,
    ) async throws -> (options: PasswordGenerationOptions, isPolicyInEffect: Bool) {
        defer { getEffectivePasswordGenerationOptionsCalled = true }
        getEffectivePasswordGenerationOptionsRules = rules
        let options = try await getPasswordGenerationOptions()
        return (options, getEffectivePasswordGenerationOptionsIsPolicyInEffect)
    }

    func getPasswordGenerationOptions() async throws -> PasswordGenerationOptions {
        defer { getPasswordGenerationOptionsCalled = true }
        return try getPasswordGenerationOptionsResult.get()
    }

    func getUsernameGenerationOptions() async throws -> UsernameGenerationOptions {
        defer { getUsernameGenerationOptionsCalled = true }
        return try getUsernameGenerationOptionsResult.get()
    }

    func passwordRulesRequest(rules: String) async -> PasswordGeneratorRequest? {
        passwordRulesRequestRules = rules
        return passwordRulesRequestResult
    }

    func setPasswordGenerationOptions(_ options: PasswordGenerationOptions) async throws {
        passwordGenerationOptions = options
        try setPasswordGenerationOptionsResult.get()
    }

    func setUsernameGenerationOptions(_ options: UsernameGenerationOptions) async throws {
        usernameGenerationOptions = options
        try setUsernameGenerationOptionsResult.get()
    }
}

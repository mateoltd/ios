import BitwardenKit
import BitwardenSdk
import Combine

/// A protocol for a `GeneratorRepository` which manages access to the data needed by the UI layer.
///
protocol GeneratorRepository: AnyObject {
    // MARK: Password History

    /// Adds a generated password to the user's password history.
    ///
    /// - Parameter passwordHistory: The generated password to add.
    ///
    func addPasswordHistory(_ passwordHistory: PasswordHistoryView) async throws

    /// Removes all of the entries from the user's password history.
    ///
    func clearPasswordHistory() async throws

    /// A publisher for the user's password history items.
    ///
    /// - Returns: A publisher for the user's password history items which will be notified as the
    ///     data changes.
    ///
    func passwordHistoryPublisher() async throws -> AsyncThrowingPublisher<AnyPublisher<[PasswordHistoryView], Error>>

    // MARK: Generator

    /// Generates a master password.
    ///
    /// - Returns: The generated master password.
    ///
    func generateMasterPassword() async throws -> String

    /// Generates a passphrase based on the passphrase settings.
    ///
    /// - Parameter settings: The settings used to generate the passphrase.
    /// - Parameter isPreAuth: Whether this is called without authentication.
    /// - Returns: The generated passphrase.
    ///
    func generatePassphrase(settings: PassphraseGeneratorRequest, isPreAuth: Bool) async throws -> String

    /// Generates a password based on the password settings.
    ///
    /// - Parameter settings: The settings used to generate the password.
    /// - Returns: The generated password.
    ///
    func generatePassword(settings: PasswordGeneratorRequest) async throws -> String

    /// Generates a username based on the username settings.
    ///
    /// - Parameter settings: The settings used to generate the username.
    /// - Returns: The generated username.
    ///
    func generateUsername(settings: AppUsernameGeneratorRequest) async throws -> String

    func loadBoundEmailAlias(_ target: BoundEmailAlias) async throws -> EmailAliasResult
    func refreshEmailAlias(_ alias: EmailAliasResult) async throws -> EmailAliasResult
    func recoverEmailAliases(baseUrl: String) async throws -> [EmailAliasResult]
    func emailAliasContacts(
        _ alias: EmailAliasResult,
        operation: EmailAliasContactOperation,
    ) async throws -> [SendReplyIdentity]

    /// Loads a SimpleLogin profile and cached alias only from the encrypted local vault.
    func loadEmailAliasProfile(baseUrl: String) async throws -> EmailAliasProfile?

    /// Creates a SimpleLogin alias in response to an explicit user action.
    func createEmailAlias(token: String, baseUrl: String, hostname: String?) async throws -> EmailAliasResult

    /// Explicitly changes an alias's forwarding state.
    func setEmailAliasEnabled(_ alias: EmailAliasResult, enabled: Bool) async throws -> EmailAliasResult

    /// Explicitly deletes an alias.
    func deleteEmailAlias(_ alias: EmailAliasResult) async throws -> EmailAliasResult

    /// Explicitly reconciles provider and encrypted vault state.
    func reconcileEmailAliases(baseUrl: String) async throws -> EmailAliasResult?

    /// Cancels provider operations and clears decrypted alias state.
    func cancelEmailAliasOperations() async

    /// Gets the user's saved password generation options with policy and password rules applied.
    ///
    /// - Parameter rules: An optional password rules string (from the AutoFill credential API) to
    ///   apply on top of saved options.
    /// - Returns: The effective options and whether an org policy is in effect.
    ///
    func getEffectivePasswordGenerationOptions(
        rules: String?,
    ) async throws -> (options: PasswordGenerationOptions, isPolicyInEffect: Bool)

    /// Gets the password generation options for the active account.
    ///
    /// - Returns: The password generation options for the account.
    ///
    func getPasswordGenerationOptions() async throws -> PasswordGenerationOptions

    /// Gets the username generation options for the active account.
    ///
    /// - Returns: The username generation options for the account.
    ///
    func getUsernameGenerationOptions() async throws -> UsernameGenerationOptions

    /// Parses a password rules string into a `PasswordGeneratorRequest` that encodes the
    /// site-specific constraints (minimum length, required character classes, etc.).
    ///
    /// - Parameter rules: The password rules string from the AutoFill credential API.
    /// - Returns: The parsed request, or `nil` if the string is absent or unparsable.
    ///
    func passwordRulesRequest(rules: String) async -> PasswordGeneratorRequest?

    /// Sets the password generation options for the active account.
    ///
    /// - Parameter options: The user's password generation options.
    ///
    func setPasswordGenerationOptions(_ options: PasswordGenerationOptions) async throws

    /// Sets the username generation options for the active account.
    ///
    /// - Parameter options: The user's username generation options.
    ///
    func setUsernameGenerationOptions(_ options: UsernameGenerationOptions) async throws
}

extension GeneratorRepository {
    /// Generates a passphrase based on the passphrase settings.
    ///
    /// - Parameter settings: The settings used to generate the passphrase.
    /// - Returns: The generated passphrase.
    ///
    func generatePassphrase(settings: PassphraseGeneratorRequest) async throws -> String {
        try await generatePassphrase(settings: settings, isPreAuth: false)
    }
}

// MARK: - DefaultGeneratorRepository

/// A default implementation of a `GeneratorRepository`.
///
class DefaultGeneratorRepository {
    // MARK: Properties

    /// The service that handles common client functionality such as encryption and decryption.
    let clientService: ClientService

    /// The data store that handles performing data requests for the generator.
    let dataStore: GeneratorDataStore

    /// The service used by the application to report non-fatal errors.
    let errorReporter: ErrorReporter

    /// The service that owns encrypted alias connection state and explicit provider operations.
    let emailAliasService: EmailAliasService

    /// The isolated boundary for existing create-only forwarded-email services.
    let forwardedEmailAliasGenerator: ForwardedEmailAliasGenerator

    /// The service used for evaluating policy.
    let policyService: PolicyService

    /// The service used by the application to manage account state.
    let stateService: StateService

    // MARK: Initialization

    /// Initialize a `DefaultGeneratorRepository`
    ///
    /// - Parameters:
    ///   - clientService: The service that handles common client functionality such as encryption and decryption.
    ///   - dataStore: The data store that handles performing data requests for the generator.
    ///   - errorReporter: The service used by the application to report non-fatal errors.
    ///   - policyService: The service used for evaluating policy.
    ///   - stateService: The service used by the application to manage account state.
    ///
    init(
        clientService: ClientService,
        dataStore: GeneratorDataStore,
        emailAliasService: EmailAliasService,
        errorReporter: ErrorReporter,
        forwardedEmailAliasGenerator: ForwardedEmailAliasGenerator = ForwardedEmailAliasGenerator(),
        policyService: PolicyService,
        stateService: StateService,
    ) {
        self.clientService = clientService
        self.dataStore = dataStore
        self.emailAliasService = emailAliasService
        self.errorReporter = errorReporter
        self.forwardedEmailAliasGenerator = forwardedEmailAliasGenerator
        self.policyService = policyService
        self.stateService = stateService
    }

    // MARK: Private

    /// Determines if the password is a duplicate of the most recent password in the history.
    ///
    /// - Parameters:
    ///   - passwordHistory: The password history item to check if it's a duplicate.
    ///   - userId: The ID of the user associated with the password.
    /// - Returns: Whether the password is a duplicate of the most recent password in the history.
    ///
    private func isDuplicateOfMostRecent(passwordHistory: PasswordHistoryView, userId: String) async throws -> Bool {
        guard let mostRecentEncrypted = try? await dataStore.fetchPasswordHistoryMostRecent(userId: userId) else {
            return false
        }
        let mostRecent = try await clientService.vault().passwordHistory().decryptList(
            list: [mostRecentEncrypted],
        ).first
        return mostRecent?.password == passwordHistory.password
    }
}

// MARK: GeneratorRepository

extension DefaultGeneratorRepository: GeneratorRepository {
    // MARK: Password History

    func addPasswordHistory(_ passwordHistory: PasswordHistoryView) async throws {
        let userId = try await stateService.getActiveAccountId()

        // Prevent adding a duplicate at the top of the list.
        guard try await !isDuplicateOfMostRecent(passwordHistory: passwordHistory, userId: userId) else { return }

        let encryptedPasswordHistory = try await clientService.vault().passwordHistory().encrypt(
            passwordHistory: passwordHistory,
        )
        try await dataStore.insertPasswordHistory(userId: userId, passwordHistory: encryptedPasswordHistory)

        // Remove any passwords past the max limit.
        try await dataStore.deletePasswordHistoryPastLimit(userId: userId, limit: Constants.maxPasswordsInHistory)
    }

    func clearPasswordHistory() async throws {
        let userId = try await stateService.getActiveAccountId()
        try await dataStore.deleteAllPasswordHistory(userId: userId)
    }

    func passwordHistoryPublisher() async throws -> AsyncThrowingPublisher<AnyPublisher<[PasswordHistoryView], Error>> {
        let userId = try await stateService.getActiveAccountId()
        return dataStore.passwordHistoryPublisher(userId: userId)
            .asyncTryMap { passwordHistory in
                try await self.clientService.vault().passwordHistory()
                    .decryptList(list: passwordHistory)
            }
            .eraseToAnyPublisher()
            .values
    }

    // MARK: Generator

    func generateMasterPassword() async throws -> String {
        try await clientService.generators(isPreAuth: true).passphrase(
            settings: PassphraseGeneratorRequest(
                numWords: 3,
                wordSeparator: "-",
                capitalize: true,
                includeNumber: true,
            ),
        )
    }

    func generatePassphrase(settings: PassphraseGeneratorRequest, isPreAuth: Bool) async throws -> String {
        try await clientService.generators(isPreAuth: isPreAuth).passphrase(settings: settings)
    }

    func generatePassword(settings: PasswordGeneratorRequest) async throws -> String {
        try await clientService.generators().password(settings: settings)
    }

    func generateUsername(settings: AppUsernameGeneratorRequest) async throws -> String {
        if case let .forwarded(service, website) = settings {
            return try await forwardedEmailAliasGenerator.generate(service: service, website: website)
        }
        guard let sdkRequest = settings.sdkRequest else { throw EmailAliasError.invalidConfiguration }
        return try await clientService.generators().username(settings: sdkRequest)
    }

    func loadBoundEmailAlias(_ target: BoundEmailAlias) async throws -> EmailAliasResult {
        try await emailAliasService.loadBoundAlias(target)
    }

    func refreshEmailAlias(_ alias: EmailAliasResult) async throws -> EmailAliasResult {
        try await emailAliasService.refreshAlias(alias)
    }

    func recoverEmailAliases(baseUrl: String) async throws -> [EmailAliasResult] {
        try await emailAliasService.recoverAliases(baseUrl: baseUrl)
    }

    func emailAliasContacts(
        _ alias: EmailAliasResult,
        operation: EmailAliasContactOperation,
    ) async throws -> [SendReplyIdentity] {
        try await emailAliasService.contacts(alias, operation: operation)
    }

    func loadEmailAliasProfile(baseUrl: String) async throws -> EmailAliasProfile? {
        try await emailAliasService.loadProfile(baseUrl: baseUrl)
    }

    func createEmailAlias(token: String, baseUrl: String, hostname: String?) async throws -> EmailAliasResult {
        try await emailAliasService.createAlias(token: token, baseUrl: baseUrl, hostname: hostname)
    }

    func setEmailAliasEnabled(_ alias: EmailAliasResult, enabled: Bool) async throws -> EmailAliasResult {
        try await emailAliasService.setAliasEnabled(alias, enabled: enabled)
    }

    func deleteEmailAlias(_ alias: EmailAliasResult) async throws -> EmailAliasResult {
        try await emailAliasService.deleteAlias(alias)
    }

    func reconcileEmailAliases(baseUrl: String) async throws -> EmailAliasResult? {
        try await emailAliasService.reconcile(baseUrl: baseUrl)
    }

    func cancelEmailAliasOperations() async {
        await emailAliasService.cancelAndClear()
    }

    func getEffectivePasswordGenerationOptions(
        rules: String?,
    ) async throws -> (options: PasswordGenerationOptions, isPolicyInEffect: Bool) {
        var options = try await getPasswordGenerationOptions()
        var isPolicyInEffect = false
        do {
            isPolicyInEffect = try await policyService.applyPasswordGenerationPolicy(options: &options)
        } catch {
            errorReporter.log(error: error)
        }

        if let rules,
           let rulesRequest = await passwordRulesRequest(rules: rules) {
            options.type = .password
            options.overridePasswordType = false
            options.apply(rulesRequest)
        }

        return (options, isPolicyInEffect)
    }

    func getPasswordGenerationOptions() async throws -> PasswordGenerationOptions {
        try await stateService.getPasswordGenerationOptions() ?? PasswordGenerationOptions()
    }

    func getUsernameGenerationOptions() async throws -> UsernameGenerationOptions {
        var options = try await stateService.getUsernameGenerationOptions() ?? UsernameGenerationOptions()
        if options.plusAddressedEmail.isEmptyOrNil {
            options.plusAddressedEmail = try? await stateService.getActiveAccount().profile.email
        }
        if options.serviceType == .simpleLogin,
           let profile = try await emailAliasService.loadProfile(baseUrl: options.simpleLoginBaseUrl ?? "") {
            options.simpleLoginApiKey = profile.token
            options.simpleLoginBaseUrl = profile.baseUrl
        }
        return options
    }

    func passwordRulesRequest(rules: String) async -> PasswordGeneratorRequest? {
        do {
            return try await clientService.generators()
                .passwordRules(rules: rules)
        } catch {
            errorReporter.log(error: error)
            return nil
        }
    }

    func setPasswordGenerationOptions(_ options: PasswordGenerationOptions) async throws {
        try await stateService.setPasswordGenerationOptions(options)
    }

    func setUsernameGenerationOptions(_ options: UsernameGenerationOptions) async throws {
        var nonSecretOptions = options
        nonSecretOptions.simpleLoginApiKey = nil
        try await stateService.setUsernameGenerationOptions(nonSecretOptions)
    }
}

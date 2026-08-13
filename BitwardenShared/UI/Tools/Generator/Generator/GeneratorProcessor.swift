import BitwardenKit
import BitwardenResources
import BitwardenSdk
import OSLog
import UIKit

/// The processor used to manage state and handle actions for the generator screen.
///
final class GeneratorProcessor: StateProcessor<GeneratorState, GeneratorAction, GeneratorEffect> {
    // swiftlint:disable:previous type_body_length

    // MARK: Types

    typealias Services = HasBillingService
        & HasConfigService
        & HasErrorReporter
        & HasGeneratorRepository
        & HasPasteboardService
        & HasPolicyService
        & HasReviewPromptService
        & HasStateService
        & HasVaultTimeoutService

    /// The behavior that should be taken after receiving a new action for generating a new value
    /// and persisting it.
    ///
    enum GenerateValueBehavior {
        /// A new value should be generated and saved to the user's password history based on the
        /// `shouldSave` associated value (saving the value only applies to generated passwords).
        case generateNewValue(shouldSave: Bool)

        /// The existing generated value should be saved without generating a new value. This is
        /// used to generate a new value as the length slider changes, but only save the last
        /// generated value when the slider ends editing.
        case saveExistingValue
    }

    // MARK: Private Properties

    /// The `Coordinator` that handles navigation.
    private let coordinator: AnyCoordinator<GeneratorRoute, Void>

    /// A flag set once the initial generator options have been loaded.
    private(set) var didLoadGeneratorOptions = false

    /// The key path of the currently focused text field.
    private var focusedKeyPath: KeyPath<GeneratorState, String>?

    /// The parsed password rules constraint from `state.forcedPasswordRules`, cached after load so
    /// it can be re-applied as floors on every generation without re-parsing the rules string.
    private var forcedPasswordRulesConstraint: PasswordGeneratorRequest?

    /// Whether the slider is currently in editing mode.
    private var isEditingSlider = false

    /// The task used to generate a new value so it can be cancelled if needed.
    private var generateValueTask: Task<Void, Never>?

    /// Clears view-owned decrypted alias state on logout or account switch.
    private var accountLifecycleTask: Task<Void, Never>?

    /// Clears view-owned decrypted alias state whenever the active vault locks.
    private var vaultLifecycleTask: Task<Void, Never>?

    /// The task used to load the generator options.
    private var loadGeneratorOptionsTask: Task<Void, Error>?

    /// The services used by this processor.
    private var services: Services

    // MARK: Initialization

    /// Creates a new `GeneratorProcessor`.
    ///
    /// - Parameters:
    ///   - coordinator: The `Coordinator` that handles navigation.
    ///   - services: The services used by the processor.
    ///   - state: The initial state of the processor.
    ///
    init(
        coordinator: AnyCoordinator<GeneratorRoute, Void>,
        services: Services,
        state: GeneratorState,
    ) {
        self.coordinator = coordinator
        self.services = services
        super.init(state: state)

        loadGeneratorOptionsTask = Task {
            try await loadGeneratorOptions()
        }
        let lifecycleRepository = services.generatorRepository
        let lifecycleStateService = services.stateService
        accountLifecycleTask = Task { [weak self] in
            var previousAccountId = try? await lifecycleStateService.getActiveAccountId()
            for await accountId in await lifecycleStateService.activeAccountIdPublisher().values {
                guard !Task.isCancelled, let self else { return }
                if accountId != previousAccountId {
                    clearEmailAliasState()
                    await lifecycleRepository.cancelEmailAliasOperations()
                    previousAccountId = accountId
                }
            }
        }
        let lifecycleVaultTimeoutService = services.vaultTimeoutService
        vaultLifecycleTask = Task { [weak self] in
            for await lockStatus in await lifecycleVaultTimeoutService.vaultLockStatusPublisher().values {
                guard !Task.isCancelled, let self else { return }
                if lockStatus == nil || lockStatus?.isVaultLocked == true {
                    clearEmailAliasState()
                    await lifecycleRepository.cancelEmailAliasOperations()
                }
            }
        }
    }

    deinit {
        accountLifecycleTask?.cancel()
        generateValueTask?.cancel()
        loadGeneratorOptionsTask?.cancel()
        vaultLifecycleTask?.cancel()
        let repository = services.generatorRepository
        Task { await repository.cancelEmailAliasOperations() }
    }

    // MARK: Methods

    override func perform(_ effect: GeneratorEffect) async {
        switch effect {
        case .appeared:
            await reloadGeneratorOptions()
            if state.isSimpleLoginAlias {
                await loadCachedEmailAlias()
            } else if !state.isForwardedEmailAlias {
                await generateValue(shouldSavePassword: true)
            }
            await checkLearnGeneratorActionCardEligibility()
            state.shouldShowUpgradedToPremiumActionCard = await services.billingService
                .shouldShowUpgradedToPremiumActionCard()
        case .dismissLearnGeneratorActionCard:
            await services.stateService.setLearnGeneratorActionCardStatus(.complete)
            state.isLearnGeneratorActionCardEligible = false
        case .dismissUpgradedToPremiumActionCard:
            state.shouldShowUpgradedToPremiumActionCard = false
            await services.billingService.setUpgradedToPremiumActionCardDismissed()
        case .showLearnGeneratorGuidedTour:
            state.generatorType = .password
            await services.stateService.setLearnGeneratorActionCardStatus(.complete)
            state.isLearnGeneratorActionCardEligible = false
            state.guidedTourViewState.showGuidedTour = true
        }
    }

    // swiftlint:disable:next cyclomatic_complexity function_body_length
    override func receive(_ action: GeneratorAction) {
        var generateValueBehavior: GenerateValueBehavior? = action.shouldGenerateNewValue
            ? .generateNewValue(shouldSave: true)
            : nil

        switch action {
        case .clearUrl:
            state.url = nil
        case .copyGeneratedValue:
            services.pasteboardService.copy(state.generatedValue)
            state.showCopiedValueToast()
            Task {
                await services.reviewPromptService.trackUserAction(.copiedOrInsertedGeneratedValue)
            }
        case .dismissPressed:
            generateValueTask?.cancel()
            clearEmailAliasState()
            Task { await services.generatorRepository.cancelEmailAliasOperations() }
            coordinator.navigate(to: .cancel)
        case .deleteEmailAlias:
            startEmailAliasLifecycleTask { try await self.deleteEmailAlias() }
        case let .emailAliasEnabledChanged(enabled):
            startEmailAliasLifecycleTask { try await self.setEmailAliasEnabled(enabled) }
        case let .emailTypeChanged(emailType):
            state.usernameState.updateEmailType(emailType)
        case .reconcileEmailAliases:
            startEmailAliasLifecycleTask { try await self.reconcileEmailAliases() }
        case .fillGeneratedValue:
            guard !state.generatedValue.isEmpty,
                  state.emailAliasResult?.status != .deleted
            else { return }
            coordinator.navigate(
                to: .complete(
                    type: state.generatorType,
                    value: state.generatedValue,
                    aliasReference: state.emailAliasResult?.reference,
                ),
            )
            Task {
                await services.reviewPromptService.trackUserAction(.copiedOrInsertedGeneratedValue)
            }
        case let .generatorTypeChanged(generatorType):
            state.generatorType = generatorType
        case .refreshGeneratedValue:
            // Generating a new value happens below.
            break
        case .showPasswordHistory:
            coordinator.navigate(to: .generatorHistory)
        case let .sliderEditingChanged(_, isEditing):
            isEditingSlider = isEditing
            if !isEditing {
                // When the slider ends editing, save the existing generated value without generating a new one.
                generateValueBehavior = .saveExistingValue
            }
        case let .sliderValueChanged(field, value):
            guard state.shouldGenerateNewValueOnSliderValueChanged(value, keyPath: field.keyPath) else {
                generateValueBehavior = nil
                break
            }
            state[keyPath: field.keyPath] = value
            if isEditingSlider {
                generateValueBehavior = .generateNewValue(shouldSave: false)
            }
        case let .stepperValueChanged(field, value):
            state[keyPath: field.keyPath] = value
        case let .textFieldFocusChanged(keyPath):
            focusedKeyPath = keyPath
        case let .textFieldIsPasswordVisibleChanged(field, value):
            guard let isPasswordVisibleKeyPath = field.isPasswordVisibleKeyPath else { break }
            state[keyPath: isPasswordVisibleKeyPath] = value
        case let .textValueChanged(field, value):
            // SwiftUI TextField likes to send multiple changes via the binding. So if the text
            // field is equal to the state's value, return early.
            guard value != state[keyPath: field.keyPath] else { return }
            state[keyPath: field.keyPath] = value

            if state.isForwardedEmailAlias {
                state.emailAliasResult = nil
                state.generatedValue = ""
            }

            if field.keyPath == \.passwordState.wordSeparator, value.count > 1 {
                state[keyPath: field.keyPath] = String(value.prefix(1))
            }

            if let focusedKeyPath {
                let shouldGenerateNewValue = state.shouldGenerateNewValueOnTextValueChanged(keyPath: focusedKeyPath)
                generateValueBehavior = shouldGenerateNewValue ? .generateNewValue(shouldSave: true) : nil
            }
        case let .toastShown(newValue):
            state.toast = newValue
        case let .toggleValueChanged(field, isOn):
            state[keyPath: field.keyPath] = isOn
        case let .usernameForwardedEmailServiceChanged(forwardedEmailService):
            state.usernameState.forwardedEmailService = forwardedEmailService
            state.emailAliasResult = nil
            state.generatedValue = ""
        case let .usernameGeneratorTypeChanged(usernameGeneratorType):
            state.usernameState.usernameGeneratorType = usernameGeneratorType
            state.emailAliasResult = nil
        case .viewDisappeared:
            generateValueTask?.cancel()
            clearEmailAliasState()
            Task { await services.generatorRepository.cancelEmailAliasOperations() }
        case let .guidedTourViewAction(action):
            state.guidedTourViewState.updateStateForGuidedTourViewAction(action)
        case .learnMoreAboutPremium:
            state.url = ExternalLinksConstants.learnMoreAboutPremium
            state.shouldShowUpgradedToPremiumActionCard = false
            Task { await services.billingService.setUpgradedToPremiumActionCardDismissed() }
        }

        if state.isForwardedEmailAlias, action != .refreshGeneratedValue {
            generateValueBehavior = nil
        }

        if let generateValueBehavior {
            generateValueTask?.cancel()
            generateValueTask = Task {
                switch generateValueBehavior {
                case let .generateNewValue(shouldSave):
                    await generateValue(shouldSavePassword: shouldSave)
                case .saveExistingValue:
                    await saveExistingGeneratedValue()
                }
                await saveGeneratorOptions()
            }
        }
    }

    // MARK: Private

    /// Checks the eligibility of the generator Login action card.
    ///
    private func checkLearnGeneratorActionCardEligibility() async {
        state.isLearnGeneratorActionCardEligible = await services.stateService
            .getLearnGeneratorActionCardStatus() == .incomplete
    }

    /// Generate a new passphrase.
    ///
    /// - Parameter settings: The passphrase generator settings used to generate a new password.
    ///
    func generatePassphrase(settings: PassphraseGeneratorRequest) async {
        do {
            let passphrase = try await services.generatorRepository.generatePassphrase(
                settings: settings,
            )
            try Task.checkCancellation()
            try await setGeneratedValue(passphrase)
        } catch is CancellationError {
            // No-op: don't log or alert for cancellation errors.
        } catch {
            Logger.application.error("Generator: error generating passphrase: \(error)")
        }
    }

    /// Generate a new password.
    ///
    /// - Parameters:
    ///   - settings: The password generator settings used to generate a new password.
    ///   - shouldSavePassword: Whether the generated password should be saved.
    ///
    func generatePassword(settings: PasswordGeneratorRequest, shouldSavePassword: Bool) async {
        do {
            let password = try await services.generatorRepository.generatePassword(
                settings: settings,
            )
            try Task.checkCancellation()
            try await setGeneratedValue(password, shouldSavePassword: shouldSavePassword)
        } catch is CancellationError {
            // No-op: don't log or alert for cancellation errors.
        } catch {
            await coordinator.showErrorAlert(error: error)
            Logger.application.error("Generator: error generating password: \(error)")
        }
    }

    /// Generate a new username.
    ///
    func generateUsername() async {
        state.generatedValue = Constants.defaultGeneratedUsername
        do {
            if state.isSimpleLoginAlias {
                announce(Localizations.emailAliasCreating)
                let result = try await services.generatorRepository.createEmailAlias(
                    token: state.usernameState.simpleLoginAPIKey,
                    baseUrl: state.usernameState.simpleLoginSelfHostServerUrl,
                    hostname: state.usernameState.emailWebsite,
                )
                try Task.checkCancellation()
                state.emailAliasResult = result
                try await setGeneratedValue(result.address)
                announce(result.status == .unknown
                    ? Localizations.emailAliasOutcomeUnknown
                    : Localizations.emailAliasCreated)
                return
            }
            guard let usernameGeneratorRequest = try state.usernameState.usernameGeneratorRequest() else {
                return
            }

            let username = try await services.generatorRepository.generateUsername(
                settings: usernameGeneratorRequest,
            )
            try Task.checkCancellation()
            try await setGeneratedValue(username)
        } catch is CancellationError {
            // No-op: don't log or alert for cancellation errors.
        } catch {
            if state.isForwardedEmailAlias {
                showEmailAliasError(error)
            } else {
                await coordinator.showErrorAlert(error: error)
                Logger.application.error("Generator: error generating username: \(error)")
            }
        }
    }

    /// Generates a new value based on the current settings.
    ///
    /// - Parameter shouldSavePassword: Whether a generated password should be saved. This is
    ///     ignored if not generating a password.
    ///
    func generateValue(shouldSavePassword: Bool) async {
        do {
            // Wait for the generator options to finish loading before generating a value.
            try await loadGeneratorOptionsTask?.value

            switch state.generatorType {
            case .passphrase, .password:
                let (type, passwordState) = await validatePasswordOptionsAndApplyPolicies()
                // It's possible that applying a policy changes the generator type, so a second
                // switch on the type is needed.
                switch type {
                case .passphrase:
                    await generatePassphrase(settings: passwordState.passphraseGeneratorRequest)
                case .password:
                    await generatePassword(
                        settings: passwordState.passwordGeneratorRequest,
                        shouldSavePassword: shouldSavePassword,
                    )
                case .username:
                    // We shouldn't get here since validating the password options shouldn't switch
                    // to the username generator.
                    await generateUsername()
                }
            case .username:
                await generateUsername()
            }
        } catch {
            services.errorReporter.log(error: error)
            coordinator.showAlert(.defaultAlert(title: Localizations.anErrorHasOccurred))
        }
    }

    /// Fetches the user's saved generator options and updates the state with the previous selections.
    ///
    func loadGeneratorOptions() async throws {
        let (passwordOptions, isPolicyInEffect) = try await services.generatorRepository
            .getEffectivePasswordGenerationOptions(rules: state.forcedPasswordRules)
        if let rules = state.forcedPasswordRules {
            forcedPasswordRulesConstraint = await services.generatorRepository.passwordRulesRequest(rules: rules)
        }
        state.isPolicyInEffect = isPolicyInEffect
        state.setGeneratorType(passwordGeneratorType: passwordOptions.type)
        state.passwordState.update(with: passwordOptions)

        let usernameOptions = try await services.generatorRepository.getUsernameGenerationOptions()
        state.usernameState.update(with: usernameOptions)
        didLoadGeneratorOptions = true
    }

    /// Loads a cached alias from the encrypted local vault without contacting the provider.
    private func loadCachedEmailAlias() async {
        do {
            guard let profile = try await services.generatorRepository.loadEmailAliasProfile(
                baseUrl: state.usernameState.simpleLoginSelfHostServerUrl,
            ) else { return }
            state.usernameState.simpleLoginAPIKey = profile.token
            state.usernameState.simpleLoginSelfHostServerUrl = profile.baseUrl
            if let alias = profile.cachedAlias, alias.status != .deleted {
                state.emailAliasResult = alias
                state.generatedValue = alias.address
                announce(emailAliasStatusAnnouncement(alias.status))
            }
        } catch is CancellationError {
            // Cancellation is expected on lock, logout, account switch, and extension expiry.
        } catch {
            showEmailAliasError(error)
        }
    }

    /// Starts one explicit alias lifecycle operation, cancelling any previous operation.
    private func startEmailAliasLifecycleTask(
        _ operation: @escaping @MainActor () async throws -> Void,
    ) {
        generateValueTask?.cancel()
        generateValueTask = Task {
            do {
                try await operation()
            } catch is CancellationError {
                // Cancellation is expected during vault lifecycle transitions.
            } catch {
                showEmailAliasError(error)
            }
        }
    }

    private func setEmailAliasEnabled(_ enabled: Bool) async throws {
        guard let alias = state.emailAliasResult else { return }
        let updated = try await services.generatorRepository.setEmailAliasEnabled(alias, enabled: enabled)
        try Task.checkCancellation()
        state.emailAliasResult = updated
        announce(emailAliasStatusAnnouncement(updated.status))
    }

    private func deleteEmailAlias() async throws {
        guard let alias = state.emailAliasResult else { return }
        let deleted = try await services.generatorRepository.deleteEmailAlias(alias)
        try Task.checkCancellation()
        state.emailAliasResult = deleted
        state.generatedValue = ""
        announce(Localizations.emailAliasDeleted)
    }

    private func reconcileEmailAliases() async throws {
        let alias = try await services.generatorRepository.reconcileEmailAliases(
            baseUrl: state.usernameState.simpleLoginSelfHostServerUrl,
        )
        try Task.checkCancellation()
        state.emailAliasResult = alias
        state.generatedValue = alias?.address ?? ""
        if let alias {
            announce(emailAliasStatusAnnouncement(alias.status))
        }
    }

    private func clearEmailAliasState() {
        if state.emailAliasResult != nil {
            state.generatedValue = ""
        }
        state.emailAliasResult = nil
        state.usernameState.simpleLoginAPIKey = ""
    }

    private func emailAliasStatusAnnouncement(_ status: EmailAliasLifecycleStatus) -> String {
        switch status {
        case .enabled: Localizations.emailAliasStatusEnabled
        case .disabled: Localizations.emailAliasStatusDisabled
        case .deleted: Localizations.emailAliasStatusDeleted
        case .unknown: Localizations.emailAliasStatusUnknown
        case .conflict: Localizations.emailAliasStatusConflict
        }
    }

    private func showEmailAliasError(_ error: Error) {
        let message: String = switch error {
        case EmailAliasError.operationOutcomeUnknown:
            Localizations.emailAliasOutcomeUnknown
        case EmailAliasError.conflict,
             EmailAliasError.invalidEncryptedState:
            Localizations.emailAliasConflict
        default:
            Localizations.anErrorHasOccurred
        }
        announce(message)
        coordinator.showAlert(.defaultAlert(title: message))
    }

    private func announce(_ message: String) {
        UIAccessibility.post(notification: .announcement, argument: message)
    }

    /// Re-loads generator options.
    ///
    private func reloadGeneratorOptions() async {
        do {
            try await loadGeneratorOptions()
        } catch {
            services.errorReporter.log(error: error)
        }
    }

    /// Saves the existing generated value to the user's password history.
    ///
    /// This should only be called in the case where we want to save a previously generated value,
    /// which wasn't saved, but now should be saved. This supports generating new passwords as the
    /// length slider moves around but only saves the last password when the slider ends editing.
    ///
    func saveExistingGeneratedValue() async {
        guard state.generatorType == .password else { return }
        do {
            try await saveGeneratedValue(state.generatedValue)
        } catch {
            await coordinator.showErrorAlert(error: error)
            Logger.application.error("Generator: error generating username: \(error)")
        }
    }

    /// Saves the generated value to the user's password history.
    ///
    /// - Parameter value: The generated value to save to the user's password history.
    ///
    func saveGeneratedValue(_ value: String) async throws {
        guard state.savePasswordHistory else { return }
        try await services.generatorRepository.addPasswordHistory(
            PasswordHistoryView(
                password: value,
                lastUsedDate: Date(),
            ),
        )
    }

    /// Saves the user's generation options so their selections can be persisted across app launches.
    ///
    func saveGeneratorOptions() async {
        do {
            switch state.generatorType {
            case .passphrase, .password:
                let passwordOptions = state.passwordState.passwordGenerationOptions(generatorType: state.generatorType)
                try await services.generatorRepository.setPasswordGenerationOptions(passwordOptions)
            case .username:
                try await services.generatorRepository.setUsernameGenerationOptions(
                    state.usernameState.usernameGenerationOptions,
                )
            }
        } catch {
            services.errorReporter.log(error: BitwardenError.generatorOptionsError(error: error))
        }
    }

    /// Sets a newly generated value to the state and saves it to the user's password history.
    ///
    /// - Parameters:
    ///   - value: The generated value.
    ///   - shouldSavePassword: Whether a generated password should be save. This is
    ///     ignored if not generating a password.
    ///
    func setGeneratedValue(_ value: String, shouldSavePassword: Bool = true) async throws {
        state.generatedValue = value
        if state.generatorType != .username, shouldSavePassword {
            try await saveGeneratedValue(value)
        }
    }

    /// Validates any password options to ensure the combination of options are valid and applies
    /// any policies to ensure a generated password conforms to the set policies.
    ///
    /// - Returns: A copy of the generator type and validated state, which can be used to generate
    ///     a new password or passphrase.
    ///
    func validatePasswordOptionsAndApplyPolicies() async -> (GeneratorType, GeneratorState.PasswordState) {
        state.passwordState.validateOptions()
        var passwordOptions = state.passwordState.passwordGenerationOptions(generatorType: state.generatorType)
        state.isPolicyInEffect = await (try? services.policyService
            .applyPasswordGenerationPolicy(options: &passwordOptions)) ?? false

        if let rulesConstraint = forcedPasswordRulesConstraint {
            passwordOptions.type = .password
            passwordOptions.overridePasswordType = false
            passwordOptions.apply(rulesConstraint)
        }

        state.setGeneratorType(passwordGeneratorType: passwordOptions.type)
        state.passwordState.update(with: passwordOptions)

        var policyOptions = PasswordGenerationOptions()
        _ = try? await services.policyService.applyPasswordGenerationPolicy(options: &policyOptions)
        state.policyOptions = policyOptions

        // Return the validated state to prevent any race conditions of the state being updated
        // before the value is generated.
        return (state.generatorType, state.passwordState)
    }
} // swiftlint:disable:this file_length

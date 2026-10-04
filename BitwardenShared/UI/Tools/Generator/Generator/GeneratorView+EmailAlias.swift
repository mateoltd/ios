import BitwardenKit
import BitwardenResources
import BitwardenSdk
import SwiftUI

extension GeneratorView {
    @ViewBuilder var emailAliasRecoveryView: some View {
        ContentBlock {
            VStack(alignment: .leading, spacing: 12) {
                if store.state.boundAliasSessionEnded {
                    InfoContainer(Localizations.aliasSessionEnded)
                }
                if store.state.aliasRecoveryNeeded {
                    InfoContainer(Localizations.aliasRecoveryInstructions)
                }
                Button(Localizations.reconcileEmailAliases) { store.send(.reconcileEmailAliases) }
                    .buttonStyle(.secondary(shouldFillWidth: true))
                    .accessibilityIdentifier("ReconcileEmailAliasesButton")
                if store.state.boundAlias == nil {
                    ForEach(store.state.recoveredAliases, id: \.reference) { alias in
                        Button(alias.address) { store.send(.selectRecoveredAlias(alias)) }
                            .buttonStyle(.secondary(shouldFillWidth: true))
                            .disabled(alias.status != .enabled)
                    }
                }
            }
            .padding(16)
        }
        .disabled(store.state.isAliasBusy || store.state.boundAliasSessionEnded)
    }

    @ViewBuilder private var emailAliasContactsView: some View {
        Text(Localizations.aliasMailClientInstructions).styleGuide(.body)
        if store.state.aliasContactRecoveryNeeded { InfoContainer(Localizations.aliasContactRecovery) }
        Button(Localizations.refreshAliasContacts) { store.send(.aliasContacts(.list)) }
            .buttonStyle(.secondary(shouldFillWidth: true))
            .accessibilityIdentifier("RefreshAliasContactsButton")
        BitwardenTextField(
            title: Localizations.aliasRecipient,
            text: store.binding(get: \.aliasRecipient, send: GeneratorAction.aliasRecipientChanged),
            accessibilityIdentifier: "AliasRecipientEntry",
        )
        .textInputAutocapitalization(.never)
        .autocorrectionDisabled()
        .keyboardType(.emailAddress)
        Button(Localizations.createAliasContact) {
            store.send(.aliasContacts(.create(recipient: store.state.aliasRecipient
                    .trimmingCharacters(in: .whitespacesAndNewlines))))
        }
        .buttonStyle(.secondary(shouldFillWidth: true))
        .disabled(store.state.aliasRecipient.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        ForEach(store.state.aliasContacts, id: \.identityId) { contact in
            VStack(alignment: .leading, spacing: 8) {
                Text(contact.recipient).styleGuide(.headline)
                Text(contact.address).styleGuide(.body)
                Button(Localizations.copyReverseAlias) { store.send(.copyAliasContact(contact)) }
                    .buttonStyle(.secondary(shouldFillWidth: true))
                    .disabled(!contact.valid || contact.blocked == true)
                Button(Localizations.composeWithAlias) { store.send(.composeAliasContact(contact)) }
                    .buttonStyle(.secondary(shouldFillWidth: true))
                    .disabled(!contact.valid || contact.blocked == true)
                if let blocked = contact.blocked {
                    Button(blocked ? Localizations.unblockAliasContact : Localizations.blockAliasContact) {
                        store.send(.aliasContacts(.setBlocked(contact, !blocked)))
                    }
                    .buttonStyle(.secondary(shouldFillWidth: true))
                }
                Button(Localizations.removeAliasContact) { store.send(.aliasContacts(.remove(contact))) }
                    .buttonStyle(.secondary(isDestructive: true, shouldFillWidth: true))
            }
        }
    }

    /// Displays explicit lifecycle controls for the current provider-backed alias.
    @ViewBuilder
    func emailAliasLifecycleView(_ alias: EmailAliasResult) -> some View {
        ContentBlock(dividerLeadingPadding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                Text(Localizations.emailAliasLifecycle)
                    .styleGuide(.headline)
                    .foregroundColor(SharedAsset.Colors.textPrimary.swiftUIColor)

                Text(emailAliasStatus(alias.status))
                    .styleGuide(.body)
                    .foregroundColor(SharedAsset.Colors.textSecondary.swiftUIColor)
                    .accessibilityIdentifier("EmailAliasStatus")

                if alias.status == .enabled || alias.status == .disabled {
                    Button {
                        store.send(.emailAliasEnabledChanged(alias.status != .enabled))
                    } label: {
                        Text(alias.status == .enabled
                            ? Localizations.disableEmailAlias
                            : Localizations.enableEmailAlias)
                    }
                    .buttonStyle(.secondary(shouldFillWidth: true))
                    .accessibilityIdentifier("EmailAliasEnabledButton")
                }

                if alias.journalPersistenceFailed {
                    InfoContainer(Localizations.aliasJournalRecovery)
                }

                if alias.status == .enabled { emailAliasContactsView }

                if alias.status != .deleted {
                    Button(Localizations.deleteEmailAlias) {
                        store.send(.deleteEmailAlias)
                    }
                    .buttonStyle(.secondary(isDestructive: true, shouldFillWidth: true))
                    .accessibilityIdentifier("DeleteEmailAliasButton")
                }
            }
            .padding(16)
        }
        .disabled(store.state.isAliasBusy || store.state.boundAliasSessionEnded)
    }

    private func emailAliasStatus(_ status: EmailAliasLifecycleStatus) -> String {
        switch status {
        case .enabled: Localizations.emailAliasStatusEnabled
        case .disabled: Localizations.emailAliasStatusDisabled
        case .deleted: Localizations.emailAliasStatusDeleted
        case .unknown: Localizations.emailAliasStatusUnknown
        case .conflict: Localizations.emailAliasStatusConflict
        }
    }
}

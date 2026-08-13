import BitwardenKit
import BitwardenResources
import SwiftUI

extension GeneratorView {
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

                Button(Localizations.reconcileEmailAliases) {
                    store.send(.reconcileEmailAliases)
                }
                .buttonStyle(.secondary(shouldFillWidth: true))
                .accessibilityIdentifier("ReconcileEmailAliasesButton")

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

import Foundation

/// API model for a cipher login.
///
struct CipherLoginModel: Codable, Equatable {
    // MARK: Properties

    /// The encrypted, canonical reference to an email alias managed by a provider.
    let aliasReference: String?

    /// Whether the login should be autofilled when the page loads.
    let autofillOnPageLoad: Bool?

    /// A list of FIDO2 credentials for the login.
    let fido2Credentials: [CipherLoginFido2Credential]?

    /// The login's password.
    let password: String?

    /// The date of the password's last revision.
    let passwordRevisionDate: Date?

    /// The login's TOTP details.
    let totp: String?

    /// The login's list of URI details.
    let uris: [CipherLoginUriModel]?

    /// The login's username.
    let username: String?

    init(
        autofillOnPageLoad: Bool?,
        fido2Credentials: [CipherLoginFido2Credential]?,
        aliasReference: String? = nil,
        password: String?,
        passwordRevisionDate: Date?,
        totp: String?,
        uris: [CipherLoginUriModel]?,
        username: String?,
    ) {
        self.autofillOnPageLoad = autofillOnPageLoad
        self.fido2Credentials = fido2Credentials
        self.aliasReference = aliasReference
        self.password = password
        self.passwordRevisionDate = passwordRevisionDate
        self.totp = totp
        self.uris = uris
        self.username = username
    }
}

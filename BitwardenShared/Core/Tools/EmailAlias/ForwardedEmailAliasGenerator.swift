import BitwardenSdk
import Foundation

/// App request used to preserve create-only forwarded-email services after their provider-specific
/// SDK enum was removed. First-class aliases use `EmailAliasService` and the canonical alias v1 SPI.
enum AppUsernameGeneratorRequest: Equatable, Sendable {
    case word(capitalize: Bool, includeNumber: Bool)
    case subaddress(type: AppendType, email: String)
    case catchall(type: AppendType, domain: String)
    case forwarded(service: ForwardedEmailGeneratorService, website: String?)

    var sdkRequest: BitwardenSdk.UsernameGeneratorRequest? {
        switch self {
        case let .word(capitalize, includeNumber):
            .word(capitalize: capitalize, includeNumber: includeNumber)
        case let .subaddress(type, email):
            .subaddress(type: type, email: email)
        case let .catchall(type, domain):
            .catchall(type: type, domain: domain)
        case .forwarded:
            nil
        }
    }
}

/// Provider-native values exist only at the create-only boundary and are never persisted in alias
/// references, journals, telemetry, or the provider-neutral SDK contract.
enum ForwardedEmailGeneratorService: Equatable, Sendable {
    case addyIo(apiToken: String, domain: String, baseUrl: String)
    case duckDuckGo(token: String)
    case firefox(apiToken: String)
    case fastmail(apiToken: String)
    case forwardEmail(apiToken: String, domain: String)
    case simpleLogin(apiKey: String, baseUrl: String)
}

/// Preserves the existing non-first-class provider behavior. This boundary performs only explicit
/// create operations and exposes only a validated address or a neutral app error.
final class ForwardedEmailAliasGenerator: @unchecked Sendable {
    private enum Endpoint {
        static let duckDuckGo = URL(string: "https://quack.duckduckgo.com/")!
        static let fastmail = URL(string: "https://api.fastmail.com/")!
        static let firefox = URL(string: "https://relay.firefox.com/")!
        static let forwardEmail = URL(string: "https://api.forwardemail.net/")!
    }

    private let transport: AliasHTTPTransport

    init(session: URLSession? = nil) {
        transport = AliasHTTPTransport(session: session)
    }

    func generate(service: ForwardedEmailGeneratorService, website: String?) async throws -> String {
        let website = try normalizedContext(website)
        switch service {
        case let .addyIo(apiToken, domain, baseUrl):
            return try await generateAddyIo(
                token: apiToken,
                domain: domain,
                baseUrl: baseUrl,
                website: website,
            )
        case let .duckDuckGo(token):
            return try await generateDuckDuckGo(token: token)
        case let .fastmail(apiToken):
            return try await generateFastmail(token: apiToken, website: website)
        case let .firefox(apiToken):
            return try await generateFirefox(token: apiToken, website: website)
        case let .forwardEmail(apiToken, domain):
            return try await generateForwardEmail(token: apiToken, domain: domain, website: website)
        case .simpleLogin:
            // SimpleLogin is first-class and must go through encrypted dispatch journaling.
            throw EmailAliasError.invalidConfiguration
        }
    }

    private func generateAddyIo(
        token: String,
        domain: String,
        baseUrl: String,
        website: String?,
    ) async throws -> String {
        let endpoint = try configurableEndpoint(baseUrl)
        let json = try await perform(
            endpoint: endpoint,
            method: "POST",
            path: "api/v1/aliases",
            headers: [
                "Authorization": "Bearer \(credential(token))",
                "X-Requested-With": "XMLHttpRequest",
            ],
            body: [
                "domain": hostname(domain),
                "description": description(website),
            ],
            mutation: true,
        )
        guard let object = json as? [String: Any],
              let data = object["data"] as? [String: Any],
              let address = data["email"] as? String
        else { throw EmailAliasError.operationOutcomeUnknown }
        return try email(address, mutation: true)
    }

    private func generateDuckDuckGo(token: String) async throws -> String {
        let json = try await perform(
            endpoint: Endpoint.duckDuckGo,
            method: "POST",
            path: "api/email/addresses",
            headers: ["Authorization": "Bearer \(credential(token))"],
            body: [:],
            mutation: true,
        )
        guard let object = json as? [String: Any], let localPart = object["address"] as? String,
              !localPart.isEmpty, localPart.utf8.count <= 128,
              localPart.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
        else { throw EmailAliasError.operationOutcomeUnknown }
        return try email("\(localPart)@duck.com", mutation: true)
    }

    private func generateFirefox(token: String, website: String?) async throws -> String {
        var body: [String: Any] = [
            "enabled": true,
            "description": firefoxDescription(website),
        ]
        if let website { body["generated_for"] = website }
        let json = try await perform(
            endpoint: Endpoint.firefox,
            method: "POST",
            path: "api/v1/relayaddresses/",
            headers: ["Authorization": "Token \(credential(token))"],
            body: body,
            mutation: true,
        )
        guard let object = json as? [String: Any], let address = object["full_address"] as? String else {
            throw EmailAliasError.operationOutcomeUnknown
        }
        return try email(address, mutation: true)
    }

    private func generateForwardEmail(token: String, domain: String, website: String?) async throws -> String {
        let domain = try hostname(domain)
        let basic = try Data("\(credential(token)):".utf8).base64EncodedString()
        var body: [String: Any] = ["description": description(website)]
        if let website { body["labels"] = website }
        let json = try await perform(
            endpoint: Endpoint.forwardEmail,
            method: "POST",
            path: "v1/domains/\(domain)/aliases",
            headers: ["Authorization": "Basic \(basic)"],
            body: body,
            mutation: true,
        )
        guard let object = json as? [String: Any],
              let name = object["name"] as? String,
              let responseDomain = object["domain"] as? [String: Any]
        else { throw EmailAliasError.operationOutcomeUnknown }
        return try email("\(name)@\((responseDomain["name"] as? String) ?? domain)", mutation: true)
    }

    private func generateFastmail(token: String, website: String?) async throws -> String {
        let token = try credential(token)
        let accountJson = try await perform(
            endpoint: Endpoint.fastmail,
            method: "GET",
            path: ".well-known/jmap",
            headers: ["Authorization": "Bearer \(token)"],
            mutation: false,
        )
        guard let accountObject = accountJson as? [String: Any],
              let accounts = accountObject["primaryAccounts"] as? [String: Any],
              let accountId = accounts["https://www.fastmail.com/dev/maskedemail"] as? String,
              !accountId.isEmpty,
              accountId.utf8.count <= 256
        else { throw EmailAliasError.providerRejected }
        let json = try await perform(
            endpoint: Endpoint.fastmail,
            method: "POST",
            path: "jmap/api/",
            headers: ["Authorization": "Bearer \(token)"],
            body: fastmailRequestBody(accountId: accountId, website: website),
            mutation: true,
        )
        guard let object = json as? [String: Any],
              let responses = object["methodResponses"] as? [Any],
              let first = responses.first as? [Any],
              first.first as? String == "MaskedEmail/set",
              first.count > 1,
              let value = first[1] as? [String: Any],
              let created = value["created"] as? [String: Any],
              let masked = created["new-masked-email"] as? [String: Any],
              let address = masked["email"] as? String
        else { throw EmailAliasError.operationOutcomeUnknown }
        return try email(address, mutation: true)
    }

    private func fastmailRequestBody(accountId: String, website: String?) -> [String: Any] {
        [
            "using": ["https://www.fastmail.com/dev/maskedemail", "urn:ietf:params:jmap:core"],
            "methodCalls": [
                [
                    "MaskedEmail/set",
                    [
                        "accountId": accountId,
                        "create": [
                            "new-masked-email": [
                                "state": "enabled",
                                "description": "",
                                "forDomain": (website as Any?) ?? NSNull(),
                                "emailPrefix": NSNull(),
                            ],
                        ],
                    ],
                    "0",
                ],
            ],
        ]
    }

    private func perform(
        endpoint: URL,
        method: String,
        path: String,
        headers: [String: String],
        body: [String: Any]? = nil,
        mutation: Bool,
    ) async throws -> Any {
        do {
            return try await transport.json(
                endpoint: endpoint,
                method: method,
                path: path,
                headers: headers,
                body: body,
                mutation: mutation,
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as AliasError {
            switch error {
            case .InvalidInput, .LocalSecurityFailure:
                throw EmailAliasError.invalidConfiguration
            case .OutcomeUnknown:
                throw EmailAliasError.operationOutcomeUnknown
            default:
                throw EmailAliasError.providerRejected
            }
        } catch {
            throw mutation ? EmailAliasError.operationOutcomeUnknown : EmailAliasError.providerRejected
        }
    }

    private func configurableEndpoint(_ value: String) throws -> URL {
        guard let canonical = AliasSyncValidation.canonicalEndpoint(value), let url = URL(string: canonical) else {
            throw EmailAliasError.invalidConfiguration
        }
        return url
    }

    private func credential(_ value: String) throws -> String {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty, normalized.utf8.count <= 16384,
              !normalized.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else { throw EmailAliasError.invalidConfiguration }
        return normalized
    }

    private func hostname(_ value: String) throws -> String {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty, normalized.utf8.count <= 253,
              normalized.unicodeScalars.allSatisfy({ scalar in
                  scalar.isASCII
                      && (CharacterSet.alphanumerics.contains(scalar) || scalar.value == 46 || scalar.value == 45)
              }),
              !normalized.hasPrefix("."), !normalized.hasSuffix("."), !normalized.contains("..")
        else { throw EmailAliasError.invalidConfiguration }
        return normalized
    }

    private func normalizedContext(_ value: String?) throws -> String? {
        guard let value else { return nil }
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalized.utf8.count <= 253,
              !normalized.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else { throw EmailAliasError.invalidConfiguration }
        return normalized.isEmpty ? nil : normalized
    }

    private func email(_ value: String, mutation: Bool) throws -> String {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let parts = normalized.split(separator: "@", omittingEmptySubsequences: false)
        guard normalized.utf8.count <= 320, parts.count == 2,
              !parts[0].isEmpty, !parts[1].isEmpty,
              !normalized.contains(where: { $0.isWhitespace || $0 == "<" || $0 == ">" })
        else {
            throw mutation ? EmailAliasError.operationOutcomeUnknown : EmailAliasError.providerRejected
        }
        return normalized
    }

    private func description(_ website: String?) -> String {
        "\(website.map { "Website: \($0). " } ?? "")Generated by Bitwarden."
    }

    private func firefoxDescription(_ website: String?) -> String {
        "\(website.map { "\($0) - " } ?? "")Generated by Bitwarden."
    }
}

import BitwardenSdk
import Foundation

/// Credential-safe JSON transport shared by provider adapters. It rejects redirects so
/// authorization values are never replayed to a different origin.
final class AliasHTTPTransport: @unchecked Sendable {
    private enum Constants {
        static let responseSizeLimit = 512 * 1024
    }

    private let session: URLSession

    init(session: URLSession? = nil) {
        if let session {
            self.session = session
            return
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        self.session = URLSession(
            configuration: configuration,
            delegate: AliasRedirectRejectingDelegate(),
            delegateQueue: nil,
        )
    }

    func json(
        endpoint: URL,
        method: String,
        path: String,
        query: [URLQueryItem] = [],
        headers: [String: String] = [:],
        body: [String: Any]? = nil,
        mutation: Bool = false,
    ) async throws -> Any {
        let request = try makeRequest(
            endpoint: endpoint,
            method: method,
            path: path,
            query: query,
            headers: headers,
            body: body,
        )
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as URLError {
            if Task.isCancelled || error.code == .cancelled { throw CancellationError() }
            if mutation { throw AliasError.OutcomeUnknown }
            switch error.code {
            case .timedOut:
                throw AliasError.Timeout
            case .cannotConnectToHost, .cannotFindHost, .networkConnectionLost, .notConnectedToInternet:
                throw AliasError.Offline
            default:
                throw AliasError.ServiceUnavailable
            }
        } catch {
            throw mutation ? AliasError.OutcomeUnknown : AliasError.ServiceUnavailable
        }
        return try decode(data: data, response: response, mutation: mutation)
    }

    // swiftlint:disable:next function_parameter_count
    private func makeRequest(
        endpoint: URL,
        method: String,
        path: String,
        query: [URLQueryItem],
        headers: [String: String],
        body: [String: Any]?,
    ) throws -> URLRequest {
        guard !path.hasPrefix("/"), !path.split(separator: "/").contains("..") else {
            throw AliasError.LocalSecurityFailure
        }
        var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)
        components?.path += path
        components?.queryItems = query.isEmpty ? nil : query
        guard let url = components?.url,
              url.scheme == endpoint.scheme,
              url.host == endpoint.host,
              url.port == endpoint.port
        else { throw AliasError.LocalSecurityFailure }

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        for (name, value) in headers {
            request.setValue(value, forHTTPHeaderField: name)
        }
        if let body {
            guard JSONSerialization.isValidJSONObject(body) else { throw AliasError.InvalidInput }
            do {
                request.httpBody = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
            } catch {
                throw AliasError.LocalSecurityFailure
            }
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return request
    }

    private func decode(data: Data, response: URLResponse, mutation: Bool) throws -> Any {
        let invalidResponse: AliasError = mutation ? .OutcomeUnknown : .InvalidResponse
        guard let http = response as? HTTPURLResponse else { throw invalidResponse }
        switch http.statusCode {
        case 200 ..< 300:
            break
        case 300 ..< 400:
            throw AliasError.LocalSecurityFailure
        case 401:
            throw AliasError.AuthenticationRejected
        case 402:
            throw AliasError.QuotaExhausted
        case 403:
            throw AliasError.PermissionDenied
        case 404:
            throw AliasError.NotFound
        case 429:
            let retry = http.value(forHTTPHeaderField: "Retry-After").flatMap(UInt64.init)
            throw AliasError.RateLimited(retryAfterSeconds: retry)
        case 500 ... Int.max:
            // A server error after dispatch does not establish that a mutation was rolled back.
            throw mutation ? AliasError.OutcomeUnknown : AliasError.ServiceUnavailable
        default:
            throw invalidResponse
        }
        guard data.count <= Constants.responseSizeLimit else { throw invalidResponse }
        if let value = http.value(forHTTPHeaderField: "Content-Length"),
           let declared = Int(value),
           declared > Constants.responseSizeLimit {
            throw invalidResponse
        }
        let contentType = http.value(forHTTPHeaderField: "Content-Type")?
            .split(separator: ";", maxSplits: 1).first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard contentType == "application/json" || contentType?.hasSuffix("+json") == true else {
            throw invalidResponse
        }
        do {
            return try JSONSerialization.jsonObject(with: data)
        } catch {
            throw invalidResponse
        }
    }
}

private final class AliasRedirectRejectingDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _: URLSession,
        task _: URLSessionTask,
        willPerformHTTPRedirection _: HTTPURLResponse,
        newRequest _: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void,
    ) {
        completionHandler(nil)
    }
}

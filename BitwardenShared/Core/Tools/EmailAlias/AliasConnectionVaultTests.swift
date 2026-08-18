import BitwardenSdk
import XCTest

@testable import BitwardenShared

final class AliasConnectionVaultTests: XCTestCase {
    private let connectionId = "11111111-1111-4111-8111-111111111111"
    private let replicaId = "22222222-2222-4222-8222-222222222222"

    /// The canonical carrier round trips in hidden fields without exposing credentials in visible data.
    func test_encodeDecode_roundTripsCanonicalEncryptedCarrier() throws {
        let payload = try payload(token: String(repeating: "secret", count: 600))

        let cipher = try AliasConnectionVaultCodec.encode(
            payload,
            date: Date(timeIntervalSince1970: 1_700_000_000),
        )

        XCTAssertTrue(cipher.isAliasConnectionCarrier)
        XCTAssertEqual(cipher.name, "bitwarden.alias.connection.v1")
        XCTAssertEqual(cipher.type, .secureNote)
        XCTAssertNil(cipher.organizationId)
        XCTAssertEqual(
            cipher.fields?.filter { $0.type == .text }.map(\.name),
            ["bitwarden.alias.connection.marker"],
        )
        XCTAssertGreaterThan(cipher.fields?.count(where: { $0.type == .hidden }) ?? 0, 1)
        XCTAssertFalse((cipher.notes ?? "").contains("secret"))
        XCTAssertEqual(try AliasConnectionVaultCodec.decode(cipher), payload)
    }

    /// Carrier recognition is exact and endpoint validation rejects credential exfiltration forms.
    func test_decode_rejectsMalformedOrNonCanonicalCarrier() throws {
        let encoded = try AliasConnectionVaultCodec.encode(payload())
        let missingMarker = CipherView.fixture(
            fields: encoded.fields?.filter { $0.name != AliasConnectionSchema.markerField },
            name: AliasConnectionSchema.carrierName,
            secureNote: SecureNoteView(type: .generic),
            type: .secureNote,
        )
        XCTAssertThrowsError(try AliasConnectionVaultCodec.decode(missingMarker)) { error in
            XCTAssertEqual(error as? EmailAliasError, .invalidEncryptedState)
        }

        XCTAssertNil(AliasSyncValidation.canonicalEndpoint("https://token@example.com/"))
        XCTAssertNil(AliasSyncValidation.canonicalEndpoint("https://example.com/?token=secret"))
        XCTAssertNil(AliasSyncValidation.canonicalEndpoint("http://example.com/"))
        XCTAssertEqual(
            AliasSyncValidation.canonicalEndpoint("https://EXAMPLE.com/api"),
            "https://example.com/api/",
        )
        XCTAssertEqual(
            AliasSyncValidation.canonicalEndpoint("http://127.0.0.1:8080/api"),
            "http://127.0.0.1:8080/api/",
        )
    }

    /// Payload chunks must be contiguous and journals cannot carry provider credentials.
    func test_decode_rejectsChunkGapsAndJournalSecrets() throws {
        let encoded = try AliasConnectionVaultCodec.encode(payload())
        let gappedFields = encoded.fields?.map { field in
            guard field.name == "\(AliasConnectionSchema.payloadField).0000" else { return field }
            return FieldView(
                name: "\(AliasConnectionSchema.payloadField).0001",
                value: field.value,
                type: field.type,
                linkedId: field.linkedId,
            )
        }
        let gapped = CipherView.fixture(
            fields: gappedFields,
            name: AliasConnectionSchema.carrierName,
            secureNote: SecureNoteView(type: .generic),
            type: .secureNote,
        )
        XCTAssertThrowsError(try AliasConnectionVaultCodec.decode(gapped))

        let malicious = try mutate(encoded) { object in
            var journal = try XCTUnwrap(object["journal"] as? [String: Any])
            journal["apiToken"] = "must-not-survive"
            object["journal"] = journal
        }
        XCTAssertThrowsError(try AliasConnectionVaultCodec.decode(malicious)) { error in
            XCTAssertEqual(error as? EmailAliasError, .invalidEncryptedState)
        }
    }

    /// Unknown enum values and the superseded provider-specific carrier schema fail closed.
    func test_decode_rejectsUnknownAndProviderSpecificSchema() throws {
        var withEvent = try payload()
        let identity = aliasIdentity()
        _ = try withEvent.journal.append(
            replicaId: replicaId,
            operationId: "33333333-3333-4333-8333-333333333333",
            operation: .get,
            phase: .acknowledged,
            target: identity,
            lifecycle: .enabled,
        )
        let encoded = try AliasConnectionVaultCodec.encode(withEvent)
        let unknown = try mutate(encoded) { object in
            var journal = try XCTUnwrap(object["journal"] as? [String: Any])
            var events = try XCTUnwrap(journal["events"] as? [[String: Any]])
            events[0]["operation"] = "provider-native-create"
            journal["events"] = events
            object["journal"] = journal
        }
        XCTAssertThrowsError(try AliasConnectionVaultCodec.decode(unknown)) { error in
            XCTAssertEqual(error as? EmailAliasError, .invalidEncryptedState)
        }

        let legacy = try mutate(encoded) { object in
            var connection = try XCTUnwrap(object["connection"] as? [String: Any])
            connection["providerInstance"] = "https://provider.example/"
            object["connection"] = connection
        }
        XCTAssertThrowsError(try AliasConnectionVaultCodec.decode(legacy)) { error in
            XCTAssertEqual(error as? EmailAliasError, .invalidEncryptedState)
        }
    }

    /// SDK merge is commutative and idempotent and rejects divergent reuse of one event ID.
    func test_merge_isDeterministicAndDetectsConflict() throws {
        var left = try AliasJournal.empty(connectionId: connectionId)
        let event = try left.append(
            replicaId: replicaId,
            operationId: "33333333-3333-4333-8333-333333333333",
            operation: .get,
            phase: .acknowledged,
            target: aliasIdentity(),
            lifecycle: .enabled,
        )
        var right = try AliasJournal.empty(connectionId: connectionId)
        _ = try right.append(
            replicaId: "44444444-4444-4444-8444-444444444444",
            operationId: "55555555-5555-4555-8555-555555555555",
            operation: .reconcile,
            phase: .acknowledged,
        )

        let leftRight = try AliasJournal.merged([left, right], connectionId: connectionId)
        let rightLeft = try AliasJournal.merged([right, left], connectionId: connectionId)
        XCTAssertEqual(leftRight, rightLeft)
        XCTAssertEqual(try AliasJournal.merged([leftRight, left], connectionId: connectionId), leftRight)

        let divergentEvent = AliasJournalEvent(
            version: event.version,
            eventId: event.eventId,
            operationId: event.operationId,
            replicaId: event.replicaId,
            sequence: event.sequence,
            causal: event.causal,
            operation: event.operation,
            phase: event.phase,
            target: event.target,
            lifecycle: .disabled,
            error: event.error,
        )
        let divergent = try canonicalizeAliasJournal(journal: AliasJournal(
            version: 1,
            connectionId: connectionId,
            events: [divergentEvent],
        ))
        XCTAssertThrowsError(try AliasJournal.merged([left, divergent], connectionId: connectionId)) { error in
            XCTAssertEqual(error as? EmailAliasError, .conflict)
        }
    }

    private func payload(token: String = "encrypted-provider-token") throws -> AliasConnectionVaultPayload {
        let connection = SimpleLoginAliasAdapter.makeConnection(connectionId: connectionId)
        return try AliasConnectionVaultPayload(
            version: AliasConnectionSchema.version,
            connection: connection,
            credential: AliasConnectionCredential(
                token: token,
                baseUrl: "https://app.simplelogin.io/",
            ),
            journal: AliasJournal.empty(connectionId: connectionId),
        )
    }

    private func aliasIdentity() -> AliasIdentity {
        AliasIdentity(version: 1, connectionId: connectionId, aliasId: "42", address: "alias@example.com")
    }

    private func mutate(
        _ cipher: CipherView,
        mutation: (inout [String: Any]) throws -> Void,
    ) throws -> CipherView {
        let encoded = (cipher.fields ?? [])
            .filter { $0.name?.hasPrefix("\(AliasConnectionSchema.payloadField).") == true }
            .sorted { ($0.name ?? "") < ($1.name ?? "") }
            .compactMap(\.value)
            .joined()
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: XCTUnwrap(encoded.data(using: .utf8))) as? [String: Any],
        )
        try mutation(&object)
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let value = try XCTUnwrap(String(data: data, encoding: .utf8))
        var fields = (cipher.fields ?? []).filter { field in
            field.name?.hasPrefix("\(AliasConnectionSchema.payloadField).") != true
        }
        var offset = value.startIndex
        var index = 0
        while offset < value.endIndex {
            let end = value.index(
                offset,
                offsetBy: AliasConnectionSchema.fieldPartSize,
                limitedBy: value.endIndex,
            ) ?? value.endIndex
            fields.append(FieldView(
                name: "\(AliasConnectionSchema.payloadField).\(String(format: "%04d", index))",
                value: String(value[offset ..< end]),
                type: .hidden,
                linkedId: nil,
            ))
            offset = end
            index += 1
        }
        return CipherView.fixture(
            fields: fields,
            name: AliasConnectionSchema.carrierName,
            secureNote: SecureNoteView(type: .generic),
            type: .secureNote,
        )
    }
}

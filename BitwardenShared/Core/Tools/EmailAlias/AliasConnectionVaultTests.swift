import BitwardenSdk
import XCTest

@testable import BitwardenShared

final class AliasConnectionVaultTests: XCTestCase {
    private let connectionId = "11111111-1111-4111-8111-111111111111"
    private let replicaId = "22222222-2222-4222-8222-222222222222"

    /// The shared schema round trips through canonical hidden fields without exposing the token
    /// through a generic visible field.
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
        XCTAssertGreaterThan(
            cipher.fields?.count(where: { $0.type == .hidden }) ?? 0,
            1,
        )
        XCTAssertEqual(try AliasConnectionVaultCodec.decode(cipher), payload)
    }

    /// A carrier must have the exact reserved marker and a canonical provider instance.
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

        XCTAssertNil(AliasSyncValidation.canonicalProviderInstance("https://token@example.com/"))
        XCTAssertNil(AliasSyncValidation.canonicalProviderInstance("https://example.com/?token=secret"))
        XCTAssertEqual(
            AliasSyncValidation.canonicalProviderInstance("https://EXAMPLE.com/api"),
            "https://example.com/api/",
        )
    }

    /// Payload chunks must be contiguous and sync events cannot smuggle provider credentials.
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

        let payloadField = try XCTUnwrap(encoded.fields?.first { $0.name?.hasSuffix(".0000") == true })
        let payloadData = try XCTUnwrap(payloadField.value?.data(using: .utf8))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: payloadData) as? [String: Any])
        var sync = try XCTUnwrap(object["sync"] as? [String: Any])
        var events = try XCTUnwrap(sync["events"] as? [[String: Any]])
        events[0]["apiToken"] = "must-not-survive"
        sync["events"] = events
        object["sync"] = sync
        let maliciousData = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let maliciousValue = try XCTUnwrap(String(data: maliciousData, encoding: .utf8))
        let maliciousFields = encoded.fields?.map { field in
            guard field.name == payloadField.name else { return field }
            return FieldView(
                name: field.name,
                value: maliciousValue,
                type: field.type,
                linkedId: field.linkedId,
            )
        }
        let malicious = CipherView.fixture(
            fields: maliciousFields,
            name: AliasConnectionSchema.carrierName,
            secureNote: SecureNoteView(type: .generic),
            type: .secureNote,
        )
        XCTAssertThrowsError(try AliasConnectionVaultCodec.decode(malicious)) { error in
            XCTAssertEqual(error as? EmailAliasError, .invalidEncryptedState)
        }
    }

    /// Replica merge is deterministic, retains tombstones, and rejects divergent reuse of an event ID.
    func test_merge_retainsTombstoneAndDetectsConflict() throws {
        let connection = AliasProviderConnection(
            providerInstance: "https://app.simplelogin.io/",
            connectionId: connectionId,
        )
        var left = AliasSyncDocument(replicaId: replicaId)
        let upsert = try left.append(kind: "connection-upsert", connection: connection)
        var right = AliasSyncDocument(replicaId: "33333333-3333-4333-8333-333333333333")
        let tombstone = try right.append(kind: "connection-remove", connection: connection)

        let merged = try AliasSyncDocument.merged([right, left], replicaId: replicaId)

        XCTAssertEqual(Set(merged.events.map(\.id)), [upsert.id, tombstone.id])
        XCTAssertTrue(merged.events.contains { $0.kind == "connection-remove" })
        XCTAssertEqual(merged.clock[replicaId], 1)
        XCTAssertEqual(merged.clock[right.replicaId], 1)

        var divergent = left
        divergent.events[0].reason = "divergent"
        XCTAssertThrowsError(try AliasSyncDocument.merged([left, divergent], replicaId: replicaId)) { error in
            XCTAssertEqual(error as? EmailAliasError, .conflict)
        }
    }

    private func payload(token: String = "encrypted-provider-token") throws -> AliasConnectionVaultPayload {
        let connection = AliasProviderConnection(
            providerInstance: "https://app.simplelogin.io/",
            connectionId: connectionId,
        )
        var sync = AliasSyncDocument(replicaId: replicaId)
        _ = try sync.append(kind: "connection-upsert", connection: connection)
        return AliasConnectionVaultPayload(
            version: AliasConnectionSchema.version,
            connection: connection,
            credential: AliasConnectionCredential(
                token: token,
                baseUrl: "https://app.simplelogin.io/",
            ),
            sync: sync,
        )
    }
}

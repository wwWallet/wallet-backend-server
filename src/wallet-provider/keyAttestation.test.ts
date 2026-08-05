import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { decodeJwt, decodeProtectedHeader, exportJWK } from "jose";
import {
	hashJson,
	normalizeAndThumbprintPublicJwks,
	signKeyAttestation,
} from "./keyAttestation";

test("normalizes valid public JWKs and computes stable thumbprints", async () => {
	const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
	const publicJwk = await exportJWK(publicKey);
	const first = await normalizeAndThumbprintPublicJwks([publicJwk]);
	const second = await normalizeAndThumbprintPublicJwks([{ ...publicJwk, use: "sig", alg: "ES256" }]);

	assert.deepEqual(first.jwks, [publicJwk]);
	assert.equal(first.thumbprints[0], second.thumbprints[0]);
});

test("rejects private JWK material and duplicate public keys", async () => {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
	const privateJwk = await exportJWK(privateKey);
	const publicJwk = await exportJWK(publicKey);

	await assert.rejects(() => normalizeAndThumbprintPublicJwks([privateJwk]), /Private JWK member/);
	await assert.rejects(
		() => normalizeAndThumbprintPublicJwks([publicJwk, publicJwk]),
		/The same public key cannot occur more than once/,
	);
});

test("produces a CS-04 Key Attestation without an issuer claim", async () => {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
	const publicJwk = await exportJWK(publicKey);
	const token = await signKeyAttestation({
		id: "e0732668-73e5-4d12-bb8d-2de6907f568d",
		issuedAt: 1777000000,
		expiresAt: 1777000900,
		attestedKeys: [publicJwk],
		verifiedEvidence: {
			evidenceReference: "evidence-1",
			keyStorage: ["iso_18045_high"],
			userAuthentication: ["iso_18045_high"],
			certification: "https://certifications.example/wscd/1",
		},
		statusListIndex: 8081,
		statusListUri: "https://wallet-provider.example/status/ka/7",
		statusMaintenanceExpiresAt: 1779764800,
	}, {
		privateKey,
		x5c: ["leaf-certificate"],
	});

	assert.deepEqual(decodeProtectedHeader(token), {
		alg: "ES256",
		typ: "key-attestation+jwt",
		x5c: ["leaf-certificate"],
	});
	assert.deepEqual(decodeJwt(token), {
		attested_keys: [publicJwk],
		key_storage: ["iso_18045_high"],
		user_authentication: ["iso_18045_high"],
		certification: "https://certifications.example/wscd/1",
		key_storage_status: {
			status: {
				status_list: {
					idx: 8081,
					uri: "https://wallet-provider.example/status/ka/7",
				},
			},
			exp: 1779764800,
		},
		jti: "e0732668-73e5-4d12-bb8d-2de6907f568d",
		iat: 1777000000,
		exp: 1777000900,
	});
});

test("hashes evidence independently of object property order", () => {
	assert.equal(hashJson({ b: 2, a: { d: 4, c: 3 } }), hashJson({ a: { c: 3, d: 4 }, b: 2 }));
});

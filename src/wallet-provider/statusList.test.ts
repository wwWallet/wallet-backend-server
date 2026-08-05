import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { inflateSync } from "node:zlib";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { encodeStatusList, signStatusListToken } from "./statusList";

test("encodes the draft-20 one-bit Status List test vector", () => {
	const encoded = encodeStatusList(16, [0, 3, 4, 5, 7, 8, 9, 13, 15]);

	assert.equal(encoded, "eNrbuRgAAhcBXQ");
	assert.deepEqual(inflateSync(Buffer.from(encoded, "base64url")), Buffer.from([0xb9, 0xa3]));
});

test("rejects an out-of-bounds Status List index", () => {
	assert.throws(() => encodeStatusList(10, [10]), /out of bounds/);
});

test("signs a draft-20 Status List Token", async () => {
	const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
	const token = await signStatusListToken({
		uri: "https://wallet-provider.example/status/ka/7",
		capacity: 16,
		invalidIndexes: [0],
		issuedAt: 1777000000,
		expiresAt: 1777000300,
		ttl: 300,
		signer: { privateKey, x5c: ["leaf-certificate"] },
	});

	assert.equal(decodeProtectedHeader(token).typ, "statuslist+jwt");
	const payload = decodeJwt(token);
	assert.equal(payload.sub, "https://wallet-provider.example/status/ka/7");
	assert.equal(payload.ttl, 300);
	assert.equal((payload.status_list as { bits: number }).bits, 1);
});

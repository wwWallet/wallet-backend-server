import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { Encoder, decode } from 'cbor-x';
import { testEnv } from '../config/test-environment';

const originalEnv = process.env;
const originalCwd = process.cwd();
let directory: string;

let webauthn: typeof import('./webauthn');
const encoder = new Encoder({ useRecords: false, variableMapSize: true });
const attestation = (authData: Buffer) => encoder.encode({ fmt: 'packed', authData, attStmt: { sig: Buffer.from([1, 2]) } });
const emptyFlags = {
	userPresent: false, userVerified: false, backupEligibility: false, backupState: false,
	attestedCredentialData: false, extensionData: false, rawFlagsByte: 0,
};

beforeAll(async () => {
	directory = mkdtempSync(path.join(tmpdir(), 'webauthn-test-'));
	process.chdir(directory);
	process.env = { ...testEnv };
	webauthn = await import('./webauthn');
});
afterAll(() => {
	process.env = originalEnv;
	process.chdir(originalCwd);
	if (directory) rmSync(directory, { recursive: true, force: true });
});

describe('WebAuthn options', () => {
	it('creates discovery options requiring verification for the configured RP', () => {
		const challenge = Buffer.from('challenge');
		expect(webauthn.getRpId()).toBe('wallet.example');
		for (const user of [undefined, { webauthnCredentials: [] }]) {
			expect(webauthn.makeGetOptions({ challenge, user }).publicKey).toEqual({
				rpId: 'wallet.example', challenge, allowCredentials: [], userVerification: 'required',
			});
		}
	});
});

describe('attestation decoding', () => {
	it.each([false, true])('strips attestation while preserving authenticator bytes (Uint8Array: %s)', typed => {
		const authData = Buffer.from(Array.from({ length: 80 }, (_, i) => i));
		const input = attestation(authData);
		const stripped = webauthn.stripAttestationStatement(typed ? new Uint8Array(input) : input);
		const result = decode(stripped);
		expect(result.fmt).toBe('none');
		expect(result.attStmt).toEqual({});
		expect(Buffer.from(result.authData)).toEqual(authData);
		expect(decode(input).fmt).toBe('packed');
	});
	it('throws for malformed attestation when stripping', () => {
		expect(() => webauthn.stripAttestationStatement(Buffer.from([0x58]))).toThrow();
	});
	it.each([
		['userPresent', 0x01], ['userVerified', 0x04], ['backupEligibility', 0x08],
		['backupState', 0x10], ['attestedCredentialData', 0x40], ['extensionData', 0x80],
	] as const)('decodes the %s flag independently', (name, flag) => {
		const data = Buffer.alloc(37);
		data[32] = flag;
		expect(webauthn.parseAuthenticatorFlags(new Uint8Array(attestation(data))))
			.toEqual({ ...emptyFlags, [name]: true, rawFlagsByte: flag });
	});
	it.each([Buffer.from([0xff]), encoder.encode({}), attestation(Buffer.alloc(36))])('returns safe flags for malformed or short data (%j)', input => {
		expect(webauthn.parseAuthenticatorFlags(input)).toEqual(emptyFlags);
	});
	it('extracts the AAGUID only when attested credential data is present and complete', () => {
		const data = Buffer.alloc(53);
		data[32] = 0x40;
		Buffer.from('00112233445566778899aabbccddeeff', 'hex').copy(data, 37);
		expect(webauthn.getAaguidFromAttestationObject(attestation(data))).toBe('00112233-4455-6677-8899-aabbccddeeff');
		expect(webauthn.getAaguidFromAttestationObject(attestation(data.subarray(0, 52)))).toBeUndefined();
		data[32] = 0;
		expect(webauthn.getAaguidFromAttestationObject(attestation(data))).toBeUndefined();
		expect(webauthn.getAaguidFromAttestationObject(Buffer.from([0xff]))).toBeUndefined();
	});
});

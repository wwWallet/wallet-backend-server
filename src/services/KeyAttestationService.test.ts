import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, expectTypeOf, it, vi } from 'vitest';

const log = vi.hoisted(() => ({ warn: vi.fn() }));
vi.mock('../logger', () => ({ logger: { child: () => log } }));
import { AttestationRequestValidationError, buildKeyAttestationPayload, parseKeyAttestationRequest, validatePublicAttestationKey } from './KeyAttestationService';
import type { AttackPotentialResistance, KeyAttestationOptions } from './walletProviderAttestation/types';
import type { WeBuildKeyAttestationOptions } from './walletProviderAttestation/WeBuildProfile';

const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const publicKey = ec.publicKey.export({ format: 'jwk' });
const keys = [publicKey];

describe('buildKeyAttestationPayload', () => {
	it('includes only attested keys by default', () => {
		expect(buildKeyAttestationPayload(keys)).toEqual({ attested_keys: keys });
	});

	it('includes the issuer nonce when supplied', () => {
		expect(buildKeyAttestationPayload(keys, 'issuer-nonce')).toEqual({
			attested_keys: keys, nonce: 'issuer-nonce',
		});
	});

	it('includes only explicitly configured provider claims', () => {
		const options: KeyAttestationOptions = {
			key_storage: ['iso_18045_basic'],
			user_authentication: ['iso_18045_basic'],
			certification: 'https://example.org/certification',
			status: { status_list: { idx: 1, uri: 'https://example.org/status' } },
		};
		expect(buildKeyAttestationPayload(keys, 'nonce', options)).toEqual({
			attested_keys: keys, nonce: 'nonce', ...options,
		});
	});

	it.each<AttackPotentialResistance>([
		'iso_18045_high',
		'iso_18045_moderate',
		'iso_18045_enhanced-basic',
		'iso_18045_basic',
	])('preserves the configured resistance value %s for both claims', (value) => {
		expect(buildKeyAttestationPayload(keys, undefined, {
			key_storage: [value],
			user_authentication: [value],
		})).toEqual({ attested_keys: keys, key_storage: [value], user_authentication: [value] });
	});

	// Both option types require non-empty arrays of OID4VCI resistance values.
	type ResistanceValues = [AttackPotentialResistance, ...AttackPotentialResistance[]] | undefined;
	expectTypeOf<KeyAttestationOptions['key_storage']>().toEqualTypeOf<ResistanceValues>();
	expectTypeOf<KeyAttestationOptions['user_authentication']>().toEqualTypeOf<ResistanceValues>();

	it('includes WEBUILD status together with base claims', () => {
		const options: WeBuildKeyAttestationOptions = {
			key_storage: ['iso_18045_basic'],
			key_storage_status: {
				status: { status_list: { idx: 1, uri: 'https://example.org/status' } },
				exp: 2000000000,
			},
		};
		expect(buildKeyAttestationPayload(keys, 'nonce', options)).toEqual({
			attested_keys: keys, nonce: 'nonce', ...options,
		});
	});

	it('rejects an empty set of attested keys', () => {
		expect(() => buildKeyAttestationPayload([])).toThrow('at least one key');
	});
});

describe('validatePublicAttestationKey', () => {
	it.each([true, false])('preserves public key extractability %s', (ext) => {
		expect(validatePublicAttestationKey({ ...publicKey, ext })).toEqual({ ...publicKey, ext });
	});
	it('leaves omitted extractability absent', () => {
		expect(validatePublicAttestationKey(publicKey)).not.toHaveProperty('ext');
	});
	it.each(['true', 1, null, {}, []].map((ext) => ({ ext })))('rejects invalid extractability $ext', ({ ext }) => {
		expect(() => validatePublicAttestationKey({ ...publicKey, ext })).toThrow('Invalid JWK ext');
	});
	it('accepts a valid public EC key and strips unverified metadata', () => {
		expect(validatePublicAttestationKey({ ...publicKey, alg: 'ES256', certification: 'fake', kid: 'client-key' }))
			.toEqual({ ...publicKey, alg: 'ES256' });
	});
	it.each(['P-384', 'P-521', 'secp256k1'])('accepts supported EC curve %s', (namedCurve) => {
		const key = generateKeyPairSync('ec', { namedCurve }).publicKey.export({ format: 'jwk' });
		expect(validatePublicAttestationKey(key)).toEqual(key);
	});
	it('accepts RSA and Ed25519 public signing keys', () => {
		const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' });
		const ed = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
		expect(validatePublicAttestationKey(rsa)).toEqual(rsa);
		expect(validatePublicAttestationKey(ed)).toEqual(ed);
	});
	it.each([
		null, [], 'key', {}, { kty: 'oct', k: 'secret' }, ec.privateKey.export({ format: 'jwk' }),
		{ ...publicKey, d: undefined }, { ...publicKey, x: 'x' }, { ...publicKey, x: publicKey.x + '=' },
		{ ...publicKey, x: Buffer.alloc(32).toString('base64url'), y: Buffer.alloc(32).toString('base64url') },
		{ ...publicKey, alg: 123 }, { ...publicKey, alg: 'ES256\n' }, { ...publicKey, use: 123 },
		{ ...publicKey, crv: 'toString' }, { ...publicKey, crv: undefined },
	])('rejects invalid, private or incompatible key %#', (key) => {
		expect(() => validatePublicAttestationKey(key)).toThrow();
	});
	it('rejects RSA keys below 2048 bits', () => {
		const key = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ format: 'jwk' });
		expect(() => validatePublicAttestationKey(key)).toThrow('2048');
	});
});

describe('parseKeyAttestationRequest', () => {
	it.each([undefined, null, [], 'body', {}, { jwks: [] }])('rejects missing key arrays %#', (body) => {
		expect(() => parseKeyAttestationRequest(body)).toThrow(AttestationRequestValidationError);
	});
	it('requires a nonce for key attestations', () => {
		expect(() => parseKeyAttestationRequest({ jwks: [publicKey] })).toThrow('openid4vci.nonce');
	});
	it('returns sanitized keys and the nonce', () => {
		expect(parseKeyAttestationRequest({ jwks: [{ ...publicKey, certification: 'fake' }], openid4vci: { nonce: 'nonce' } }))
			.toEqual({ keys: [publicKey], nonce: 'nonce' });
	});
	it('preserves extractability through request parsing and payload construction', () => {
		const key = { ...publicKey, ext: true };
		const { keys, nonce } = parseKeyAttestationRequest({ jwks: [key], openid4vci: { nonce: 'nonce' } });
		expect(buildKeyAttestationPayload(keys, nonce)).toEqual({ attested_keys: [key], nonce: 'nonce' });
	});
});


describe('key validation logging', () => {
	it('logs the validation reason without submitted keys or nonce', () => {
		log.warn.mockClear();
		expect(() => parseKeyAttestationRequest({
			jwks: [{ ...publicKey, d: 'private-key-secret' }], openid4vci: { nonce: 'nonce-secret' },
		})).toThrow(AttestationRequestValidationError);
		expect(log.warn).toHaveBeenCalledExactlyOnceWith(
			{ err: expect.any(Error) }, 'Invalid key attestation request',
		);
		const error = log.warn.mock.calls[0][0].err;
		expect(error.message).toBe('Private or symmetric key material is forbidden');
		expect(JSON.stringify({ ...error, message: error.message, stack: error.stack }))
			.not.toMatch(/private-key-secret|nonce-secret/);
	});

	it('does not forward arbitrary properties on caught errors', () => {
		log.warn.mockClear();
		const key = { get kty() { throw Object.assign(new Error('Invalid key'), { key: 'secret' }); } };
		expect(() => parseKeyAttestationRequest({ jwks: [key], openid4vci: { nonce: 'nonce' } }))
			.toThrow(AttestationRequestValidationError);
		expect(log.warn.mock.calls[0][0].err).not.toHaveProperty('key');
	});
});


describe('key_ops warnings', () => {
	it.each([['sign'], [], ['verify', 'sign'], 'verify', null])('warns without rejecting an otherwise valid key (%j)', (key_ops) => {
		log.warn.mockClear();
		expect(validatePublicAttestationKey({ ...publicKey, key_ops })).toEqual(publicKey);
		expect(log.warn).toHaveBeenCalledExactlyOnceWith(
			'Expected public signature verification operations in JWK key_ops',
		);
	});

	it.each([undefined, ['verify']])('does not warn for omitted or verification-only operations (%j)', (key_ops) => {
		log.warn.mockClear();
		expect(validatePublicAttestationKey({ ...publicKey, key_ops })).toEqual(publicKey);
		expect(log.warn).not.toHaveBeenCalled();
	});
});


describe('advisory JWK metadata', () => {
	it.each(['enc', 'https://example.org/custom-use'])('warns and strips non-signing use %s', (use) => {
		log.warn.mockClear();
		expect(validatePublicAttestationKey({ ...publicKey, use })).toEqual(publicKey);
		expect(log.warn).toHaveBeenCalledExactlyOnceWith('Expected signing use in JWK use; ignoring advisory metadata');
	});

	it.each(['HS256', 'ES384', 'https://example.org/custom-alg'])('warns and strips unrecognized or incompatible alg %s', (alg) => {
		log.warn.mockClear();
		expect(validatePublicAttestationKey({ ...publicKey, alg })).toEqual(publicKey);
		expect(log.warn).toHaveBeenCalledExactlyOnceWith(
			'Unrecognized or incompatible JWK algorithm; omitting advisory algorithm metadata',
		);
	});

	it('accepts Ed448 public signing keys', () => {
		const key = generateKeyPairSync('ed448').publicKey.export({ format: 'jwk' });
		expect(validatePublicAttestationKey(key)).toEqual(key);
		expect(() => validatePublicAttestationKey({ ...key, x: publicKey.x })).toThrow('Invalid Edwards');
	});

	it.each([
		{ n: Buffer.concat([Buffer.from([1]), Buffer.alloc(1023), Buffer.from([1])]).toString('base64url'), e: 'AQAB' },
		{ n: Buffer.concat([Buffer.from([128]), Buffer.alloc(254), Buffer.from([1])]).toString('base64url'),
			e: Buffer.from([1, 0, 0, 0, 1]).toString('base64url') },
	])('warns for RSA sizes outside the previous implementation limits (%#)', (parameters) => {
		log.warn.mockClear();
		const key = { kty: 'RSA', ...parameters };
		expect(validatePublicAttestationKey(key)).toEqual(key);
		expect(log.warn).toHaveBeenCalledExactlyOnceWith(
			'RSA key exceeds the usual modulus or exponent size',
		);
	});

	it.each(['AAE', 'Ag', 'AQ'])('still rejects invalid RSA exponents %s', (e) => {
		const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' });
		expect(() => validatePublicAttestationKey({ ...key, e })).toThrow('Invalid RSA');
	});
});

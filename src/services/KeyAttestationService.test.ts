import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, expectTypeOf, it } from 'vitest';
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

	it('restricts both option types to non-empty arrays of OID4VCI resistance values', () => {
		type ResistanceValues = [AttackPotentialResistance, ...AttackPotentialResistance[]] | undefined;
		expectTypeOf<KeyAttestationOptions['key_storage']>().toEqualTypeOf<ResistanceValues>();
		expectTypeOf<KeyAttestationOptions['user_authentication']>().toEqualTypeOf<ResistanceValues>();
	});

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
	it('accepts a valid public EC key and strips unverified metadata', () => {
		expect(validatePublicAttestationKey({ ...publicKey, alg: 'ES256', certification: 'fake', kid: 'client-key' }))
			.toEqual({ ...publicKey, alg: 'ES256' });
	});
	it.each(['P-384', 'P-521'])('accepts supported EC curve %s', (namedCurve) => {
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
		{ ...publicKey, alg: 'HS256' }, { ...publicKey, alg: 'ES384' }, { ...publicKey, use: 'enc' },
		{ ...publicKey, key_ops: ['sign'] }, { ...publicKey, crv: 'toString' },
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
});

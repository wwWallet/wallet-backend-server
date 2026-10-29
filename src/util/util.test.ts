import { generateKeyPairSync } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';
import { Err, Ok } from 'ts-results';
import {
	checkedUpdate,
	decideVerifiableCredentialType,
	generateCodeChallengeFromVerifier,
	generateCodeVerifier,
	isResult,
	isValidUri,
	jsonParseTaggedBinary,
	jsonStringifyTaggedBinary,
	importPrivateKeyPem,
	removeCertificateMarkers,
} from '../../src/util/util';

describe('tagged binary JSON', () => {
	it.each([
		[Buffer.alloc(0), '{"$b64u":""}'],
		[Buffer.from([0, 255, 128, 254]), '{"$b64u":"AP-A_g"}'],
	])('serializes a root buffer to the expected wire format (%j)', (bytes, json) => {
		expect(jsonStringifyTaggedBinary(bytes)).toBe(json);
		expect(jsonParseTaggedBinary(json as string)).toEqual(bytes);
	});

	it('preserves nested buffers, arrays, nulls and ordinary JSON values', () => {
		const value = {
			privateData: Buffer.from([255]),
			nested: [Buffer.alloc(0), { bytes: Buffer.from([0]) }],
			name: 'Wallet',
			count: 3,
			enabled: false,
			optional: null,
		};
		const json = jsonStringifyTaggedBinary(value);
		expect(JSON.parse(json)).toEqual({
			privateData: { $b64u: '_w' },
			nested: [{ $b64u: '' }, { bytes: { $b64u: 'AA' } }],
			name: 'Wallet',
			count: 3,
			enabled: false,
			optional: null,
		});
		expect(jsonParseTaggedBinary(json)).toEqual(value);
	});

	it('leaves untagged objects and base64-looking strings unchanged', () => {
		const value = { data: 'AP-A_g', type: 'Buffer', nested: { other: '' } };
		expect(jsonParseTaggedBinary(JSON.stringify(value))).toEqual(value);
	});

	it('rejects malformed JSON', () => {
		expect(() => jsonParseTaggedBinary('{')).toThrow(SyntaxError);
	});
});

describe('checkedUpdate', () => {
	const tag = (value: Buffer) => value.toString('hex');
	const current = Buffer.from([0, 255]);
	const next = Buffer.from([128, 1]);

	it('accepts a changed value when its expected tag matches', () => {
		const result = checkedUpdate('00ff', tag, { currentValue: current, newValue: next });
		expect(result.ok).toBe(true);
		expect(result.val).toBe(next);
		expect(current).toEqual(Buffer.from([0, 255]));
	});

	it.each(['stale', undefined])('rejects a changed value with expected tag %s without mutating either buffer', (expected) => {
		const currentValue = Buffer.from(current);
		const newValue = Buffer.from(next);
		expect(checkedUpdate(expected, tag, { currentValue, newValue }).err).toBe(true);
		expect(currentValue).toEqual(current);
		expect(newValue).toEqual(next);
	});

	it('accepts equal bytes in separate buffers despite a stale tag', () => {
		const newValue = Buffer.from(current);
		const result = checkedUpdate('stale', tag, { currentValue: current, newValue });
		expect(result.ok).toBe(true);
		expect(result.val).toBe(newValue);
	});

	it('accepts an identical reference without evaluating a tag', () => {
		const result = checkedUpdate(
			'stale',
			() => {
				throw new Error('An identical reference needs no tag');
			},
			{ currentValue: current, newValue: current },
		);
		expect(result.ok).toBe(true);
		expect(result.val).toBe(current);
	});

	it('uses strict equality for expected tags', () => {
		expect(
			checkedUpdate<string, string | number>('1', (value) => (value === 'old' ? 1 : 2), { currentValue: 'old', newValue: 'new' }).err,
		).toBe(true);
	});
});

describe('PKCE', () => {
	it('matches the RFC 7636 Appendix B S256 vector', async () => {
		// https://www.rfc-editor.org/rfc/rfc7636.html#appendix-B
		expect(await generateCodeChallengeFromVerifier('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe(
			'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
		);
	});

	it('generates independent 32-byte verifiers using the unpadded URL-safe alphabet', () => {
		const verifiers = Array.from({ length: 8 }, () => generateCodeVerifier());
		expect(new Set(verifiers).size).toBe(verifiers.length);
		for (const verifier of verifiers) {
			expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
			expect(Buffer.from(verifier, 'base64url')).toHaveLength(32);
		}
	});
});

describe('credential type classification', () => {
	it('prioritizes presentations over diploma types', () => {
		expect(decideVerifiableCredentialType(['UniversityDegreeCredential', 'VerifiablePresentation'])).toBe('Presentation');
	});

	it.each(['UniversityDegreeCredential', 'EUROPASSCredential', 'diploma'])('recognizes diploma type %s', (type) => {
		expect(decideVerifiableCredentialType(['VerifiableCredential', type])).toBe('Diploma');
	});

	it.each([[], ['VerifiableCredential', 'EmployeeCredential']])('defaults other types to attestation (%j)', (...types) => {
		expect(decideVerifiableCredentialType(types as string[])).toBe('Attestation');
	});
});

describe('URI validation', () => {
	it.each(['https://wallet.example/path?query=1#fragment', 'http://localhost:8002', 'openid4vp://authorize'])(
		'accepts absolute URI %s',
		(uri) => {
			expect(isValidUri(uri)).toBe(true);
		},
	);

	it.each(['', '/relative/path', 'wallet.example', 'http://', 'https://example.com:99999'])('rejects invalid or relative URI %j', (uri) => {
		expect(isValidUri(uri)).toBe(false);
	});
});

describe('small utility boundaries', () => {
	it('recognizes both successful and failed Results', () => {
		expect(isResult(Ok('value'))).toBe(true);
		expect(isResult(Err('failure'))).toBe(true);
	});

	it.each([null, undefined, false, 0, 'value', {}, { val: 1 }])('does not treat ordinary value %j as a Result', (value) => {
		expect(isResult<unknown>(value)).toBe(false);
	});

	it('removes certificate delimiters and surrounding whitespace without altering its payload', () => {
		expect(removeCertificateMarkers(' \n-----BEGIN CERTIFICATE-----\nYWJj\nZGVm\n-----END CERTIFICATE-----\n ')).toBe('YWJj\nZGVm');
	});
});

describe('PKCS8 private-key import', () => {
	it('imports a generated ES256 key that signs a JWT verifiable with its public key', async () => {
		const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
		const pem = pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
		const imported = await importPrivateKeyPem(pem, 'ES256');
		expect(imported).toBeDefined();
		const token = await new SignJWT({ purpose: 'unit-test' }).setProtectedHeader({ alg: 'ES256' }).sign(imported!);
		const result = await jwtVerify(token, pair.publicKey);
		expect(result.payload.purpose).toBe('unit-test');
		expect(result.protectedHeader.alg).toBe('ES256');
	});

	it('returns no key for an invalid PEM', async () => {
		expect(await importPrivateKeyPem('invalid synthetic PEM', 'ES256')).toBeUndefined();
	});
});

import { describe, expect, it } from 'vitest';
import { attackPotentialResistanceSchema, oid4vciKeyAttestationClaimsSchema } from './types';
import { weBuildKeyAttestationClaimsSchema } from './WeBuildProfile';

describe('key attestation claim schemas', () => {
	it('allows base claims to be omitted before the shared builder and signer run', () => {
		expect(oid4vciKeyAttestationClaimsSchema.parse({})).toEqual({});
	});

	it('models all OID4VCI Appendix D.1 payload claims', () => {
		const claims = {
			iat: 100,
			exp: 200,
			nonce: 'nonce',
			attested_keys: [{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }],
			key_storage: ['iso_18045_high'],
			user_authentication: ['iso_18045_basic'],
			certification: 'https://example.org/certification',
			status: { status_list: { idx: 1, uri: 'https://example.org/status' } },
		};
		expect(oid4vciKeyAttestationClaimsSchema.parse(claims)).toEqual(claims);
	});

	it.each(['key_storage', 'user_authentication', 'attested_keys'])('rejects an empty %s', (claim) => {
		expect(oid4vciKeyAttestationClaimsSchema.safeParse({ [claim]: [] }).success).toBe(false);
	});

	it('rejects unsupported resistance values', () => {
		expect(attackPotentialResistanceSchema.safeParse('high').success).toBe(false);
	});

	it('makes profile requirements stricter than the base schema', () => {
		expect(weBuildKeyAttestationClaimsSchema.safeParse({}).success).toBe(false);
	});
});

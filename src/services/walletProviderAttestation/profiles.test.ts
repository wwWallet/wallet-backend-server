import { describe, expect, it } from 'vitest';
import { loadWalletProviderAttestationProfile } from './index';

const keys = [{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }];
const status = { status: { status_list: { idx: 1, uri: 'https://example.org/status' } }, exp: 2000000000 };
describe('key attestation profiles', () => {
	it.each(['OID4VCI', 'WEBUILD'])('selects %s', (id) => {
		expect(loadWalletProviderAttestationProfile(id).id).toBe(id);
	});
	it.each(['', 'DEFAULT', 'typo', 'toString', '__proto__'])('rejects unknown profile %s', (id) => {
		expect(() => loadWalletProviderAttestationProfile(id)).toThrow('Unknown');
	});
	it('places the allocated key status at the OID4VCI top level', () => {
		expect(loadWalletProviderAttestationProfile('OID4VCI').buildKeyAttestationPayload({ keys, keyStorageStatus: status }))
			.toEqual({ attested_keys: keys, status: status.status });
	});
	it('restores WEBUILD key options alongside the allocated status', () => {
		expect(loadWalletProviderAttestationProfile('WEBUILD').buildKeyAttestationPayload({ keys, nonce: 'nonce', issuer: 'https://provider.example/wallet-provider', keyStorageStatus: status }))
			.toEqual({ attested_keys: keys, nonce: 'nonce', key_storage_status: status,
				key_storage: ['iso_18045_basic'], user_authentication: ['iso_18045_basic'],
				certification: 'https://provider.example/wallet-provider/certification' });
		expect(() => loadWalletProviderAttestationProfile('WEBUILD').buildKeyAttestationPayload({ keys })).toThrow('key_storage_status');
	});
	it.each(['OID4VCI'])('%s has no certification page', (id) => {
		expect(loadWalletProviderAttestationProfile(id).getCertificationPage()).toBeUndefined();
	});

	it('publishes a WE BUILD mock certification with its keystore classification', () => {
		const page = loadWalletProviderAttestationProfile('WEBUILD').getCertificationPage();
		expect(page).toContain('<!doctype html>');
		expect(page).toContain('WE BUILD mock wallet certification');
		expect(page).toContain('Key storage type: keystore.');
		expect(page).toContain('No WSCD or keystore certification is asserted.');
	});

});


describe('wallet attestation profiles', () => {
	const key = keys[0];
	const claims = {
		wallet_name: 'Example Wallet', wallet_version: '1.0',
		wallet_solution_certification_information: 'Verified certification reference',
	};

	it('places the allocated wallet status at the OID4VCI top level', () => {
		expect(loadWalletProviderAttestationProfile('OID4VCI').buildWalletAttestationPayload({ key, clientId: 'client', issuer: 'https://provider.example/wallet-provider', clientStatus: status }))
			.toEqual({ iss: 'https://provider.example/wallet-provider', sub: 'client', cnf: { jwk: key }, status: status.status });
	});

	it.each(['WEBUILD'])('builds wallet claims for %s', (id) => {
		expect(loadWalletProviderAttestationProfile(id).buildWalletAttestationPayload({ key, clientId: 'client', issuer: 'https://provider.example/wallet-provider', claims, clientStatus: status }))
			.toEqual({ ...claims, wallet_link: 'https://webuild.wwwallet.org', client_status: status, sub: 'client', cnf: { jwk: key } });
	});

	it.each(['WEBUILD'])('requires status and validates explicit metadata for %s', (id) => {
		const profile = loadWalletProviderAttestationProfile(id);
		expect(() => profile.buildWalletAttestationPayload({ key, clientId: 'client', issuer: 'https://provider.example/wallet-provider', claims })).toThrow();
		for (const name of Object.keys(claims)) {
			expect(() => profile.buildWalletAttestationPayload({ key, clientId: 'client', issuer: 'https://provider.example/wallet-provider', clientStatus: status,
				claims: { ...claims, [name]: '' },
			})).toThrow();
		}
	});

	it.each(['OID4VCI', 'WEBUILD'])('preserves subject and key binding under %s', (id) => {
		const payload = loadWalletProviderAttestationProfile(id).buildWalletAttestationPayload({ key, clientId: 'client', issuer: 'https://provider.example/wallet-provider', clientStatus: status,
			claims: { ...claims, sub: 'override', cnf: { jwk: { kty: 'RSA' } } },
		});
		expect(payload.sub).toBe('client');
		expect(payload.cnf).toEqual({ jwk: key });
	});
});


describe('OID4VCI optional status', () => {
	const profile = loadWalletProviderAttestationProfile('OID4VCI');
	it('omits status when no reference is supplied', () => {
		expect(profile.buildKeyAttestationPayload({ keys })).toEqual({ attested_keys: keys });
		expect(profile.buildWalletAttestationPayload({ key: keys[0], clientId: 'client', issuer: 'https://provider.example/wallet-provider' }))
			.toEqual({ iss: 'https://provider.example/wallet-provider', sub: 'client', cnf: { jwk: keys[0] } });
	});
	it('preserves explicit status but gives allocated references precedence', () => {
		const explicit = { status_list: { idx: 9, uri: 'https://example.org/other' } };
		expect(profile.buildKeyAttestationPayload({ keys, claims: { status: explicit } }).status).toEqual(explicit);
		expect(profile.buildKeyAttestationPayload({ keys, claims: { status: explicit }, keyStorageStatus: status }).status)
			.toEqual(status.status);
		expect(profile.buildWalletAttestationPayload({ key: keys[0], clientId: 'client', issuer: 'https://provider.example/wallet-provider', claims: { status: explicit } }).status)
			.toEqual(explicit);
		expect(profile.buildWalletAttestationPayload({ key: keys[0], clientId: 'client', issuer: 'https://provider.example/wallet-provider', claims: { status: explicit }, clientStatus: status }).status)
			.toEqual(status.status);
	});
});


describe('OID4VCI wallet issuer', () => {
	it('uses the provider issuer even when claims contain a different issuer', () => {
		const payload = loadWalletProviderAttestationProfile('OID4VCI').buildWalletAttestationPayload({
			key: keys[0], clientId: 'client', issuer: 'https://provider.example/wallet-provider',
			claims: { iss: 'https://untrusted.example' },
		});
		expect(payload.iss).toBe('https://provider.example/wallet-provider');
	});
	it('rejects an empty issuer', () => {
		expect(() => loadWalletProviderAttestationProfile('OID4VCI').buildWalletAttestationPayload({
			key: keys[0], clientId: 'client', issuer: '',
		})).toThrow('provider issuer');
	});
});


describe('WEBUILD wallet defaults', () => {
	it('restores the lifecycle payload without requiring metadata from the router', () => {
		expect(loadWalletProviderAttestationProfile('WEBUILD').buildWalletAttestationPayload({
			key: keys[0], clientId: 'client', issuer: 'https://provider.example/wallet-provider',
			authorizationServer: 'https://as.example', attestationId: 'allocated-id', clientStatus: status,
		})).toEqual({
			jti: 'allocated-id', sub: 'client', aud: 'https://as.example', cnf: { jwk: keys[0] },
			wallet_name: 'WE BUILD wwWallet', wallet_link: 'https://webuild.wwwallet.org', wallet_version: '1.0.0',
			wallet_solution_certification_information: 'Development instance — no wallet solution certification asserted',
			client_status: status,
		});
	});
});

import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { buildWalletAttestationPayload, parseWalletAttestationRequest } from './WalletAttestationService';
import type { WeBuildWalletInstanceAttestationOptions } from './walletProviderAttestation/WeBuildProfile';

const key = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });

describe('buildWalletAttestationPayload', () => {
	it('includes only the subject and key binding by default', () => {
		expect(buildWalletAttestationPayload(key, 'wallet-client')).toEqual({
			sub: 'wallet-client', cnf: { jwk: key },
		});
	});

	it('adds explicitly configured metadata without adding other optional claims', () => {
		expect(buildWalletAttestationPayload(key, 'wallet-client', {
			wallet_name: 'Example Wallet',
		})).toEqual({
			sub: 'wallet-client', cnf: { jwk: key }, wallet_name: 'Example Wallet',
		});
	});

	it('supports explicit profile and status claims', () => {
		const options: WeBuildWalletInstanceAttestationOptions = {
			iss: 'https://provider.example', aud: 'https://as.example', jti: 'attestation-id',
			wallet_name: 'Example Wallet', wallet_link: 'https://wallet.example',
			wallet_version: '2.0', wallet_solution_certification_information: 'Certification reference',
			status: { status_list: { idx: 0, uri: 'https://provider.example/status' } },
			client_status: { status: { status_list: { idx: 0, uri: 'https://provider.example/status' } }, exp: 2000000000 },
		};
		expect(buildWalletAttestationPayload(key, 'wallet-client', options)).toEqual({
			...options, sub: 'wallet-client', cnf: { jwk: key },
		});
	});
});

describe('parseWalletAttestationRequest', () => {
	it.each([undefined, null, [], 'body', {}, { jwks: [] }])('rejects missing key arrays %#', (body) => {
		expect(() => parseWalletAttestationRequest(body)).toThrow("'jwks'");
	});
	it('requires client and authorization server identifiers', () => {
		expect(() => parseWalletAttestationRequest({ jwks: [key] })).toThrow('client_id');
		expect(() => parseWalletAttestationRequest({ jwks: [key], openid4vci: { client_id: 'client' } }))
			.toThrow('authorization_server');
	});
	it('returns validated wallet request fields', () => {
		expect(parseWalletAttestationRequest({ jwks: [key], openid4vci: {
			client_id: 'client', authorization_server: 'https://as.example',
		} })).toEqual({ key, clientId: 'client', authorizationServer: 'https://as.example' });
	});
});

import { buildWalletAttestationPayload } from '../WalletAttestationService';
import { walletAttestationOptionsSchema } from './types';
import { z } from 'zod';
import { oid4vciKeyAttestationClaimsSchema } from './types';
import { buildKeyAttestationPayload } from '../KeyAttestationService';
import type { WalletProviderAttestationProfile } from './types';

export const keyStorageStatusSchema = z.object({
	status: z.object({
		status_list: z.object({ idx: z.number().int().nonnegative(), uri: z.string().url() }),
	}),
	exp: z.number().int().positive(),
});

export type KeyStorageStatus = z.infer<typeof keyStorageStatusSchema>;

export const weBuildKeyAttestationClaimsSchema = oid4vciKeyAttestationClaimsSchema.extend({
	key_storage_status: keyStorageStatusSchema,
});
export type WeBuildKeyAttestationClaims = z.infer<typeof weBuildKeyAttestationClaimsSchema>;
export type WeBuildKeyAttestationOptions = Omit<WeBuildKeyAttestationClaims, 'iat' | 'exp' | 'attested_keys' | 'nonce'>;

export const weBuildWalletInstanceAttestationOptionsSchema = walletAttestationOptionsSchema.extend({
	wallet_name: z.string().trim().min(1),
	wallet_version: z.string().trim().min(1),
	wallet_solution_certification_information: z.string().trim().min(1),
	client_status: keyStorageStatusSchema,
});
export type WeBuildWalletInstanceAttestationOptions = z.infer<typeof weBuildWalletInstanceAttestationOptionsSchema>;

export const weBuildProfile: WalletProviderAttestationProfile = {
	id: 'WEBUILD',
	buildKeyAttestationPayload: ({ keys, nonce, issuer, claims, keyStorageStatus }) => {
		const status = keyStorageStatus ?? claims?.key_storage_status;
		if (!status) {
			throw new Error('WEBUILD requires provider key_storage_status');
		}
		const options = {
			key_storage: ['iso_18045_basic'],
			user_authentication: ['iso_18045_basic'],
			...(issuer === undefined ? {} : { certification: `${issuer.replace(/\/+$/, '')}/certification` }),
			...claims,
			key_storage_status: status,
		};
		return buildKeyAttestationPayload(keys, nonce, weBuildKeyAttestationClaimsSchema.parse(options));
	},
	buildWalletAttestationPayload: ({ key, clientId, authorizationServer, attestationId, claims, clientStatus }) => {
		const options = weBuildWalletInstanceAttestationOptionsSchema.parse({
			wallet_name: 'WE BUILD wwWallet',
			wallet_link: 'https://webuild.wwwallet.org',
			wallet_version: '1.0.0',
			wallet_solution_certification_information: 'WE BUILD Development instance — no wallet solution certification asserted',
			...claims,
			...(authorizationServer === undefined ? {} : { aud: authorizationServer }),
			...(attestationId === undefined ? {} : { jti: attestationId }),
			client_status: clientStatus ?? claims?.client_status,
		});
		return buildWalletAttestationPayload(key, clientId, options);
	},
	getCertificationPage: () =>
		'<!doctype html><html lang="en"><meta charset="utf-8">' +
		'<title>WE BUILD mock wallet certification</title><h1>WE BUILD mock wallet certification</h1>' +
		'<p>Key storage type: keystore. No WSCD certification is asserted.</p>' +
		'<p>No WSCD or keystore certification is asserted. This page is a WE BUILD integration fixture.</p></html>',
};

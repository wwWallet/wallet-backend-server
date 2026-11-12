import { buildWalletAttestationPayload } from '../WalletAttestationService';
import { buildKeyAttestationPayload } from '../KeyAttestationService';
import type { Oid4vciKeyAttestationClaims, WalletAttestationOptions, WalletProviderAttestationProfile } from './types';

export interface KeyStorageStatus {
	status: { status_list: { idx: number; uri: string } };
	exp: number;
}

export interface WeBuildKeyAttestationClaims extends Oid4vciKeyAttestationClaims {
	key_storage_status: KeyStorageStatus;
}
export type WeBuildKeyAttestationOptions = Omit<WeBuildKeyAttestationClaims, 'iat' | 'exp' | 'attested_keys' | 'nonce'>;

export interface WeBuildWalletInstanceAttestationOptions extends WalletAttestationOptions {
	wallet_name: string;
	wallet_version: string;
	wallet_solution_certification_information: string;
	client_status: KeyStorageStatus;
}

function requireStatus(status: KeyStorageStatus | undefined, name: string): KeyStorageStatus {
	if (
		!status ||
		!Number.isInteger(status.exp) ||
		status.exp <= 0 ||
		!Number.isInteger(status.status?.status_list?.idx) ||
		status.status.status_list.idx < 0
	) {
		throw new Error(`WEBUILD requires a valid ${name}`);
	}
	try {
		new URL(status.status.status_list.uri);
	} catch {
		throw new Error(`WEBUILD requires a valid ${name} URI`);
	}
	return status;
}

function requireUrl(value: string | undefined): void {
	if (value !== undefined) new URL(value);
}

export const WeBuildProfile: WalletProviderAttestationProfile = {
	id: 'WEBUILD',
	buildKeyAttestationPayload: ({ keys, nonce, issuer, claims, keyStorageStatus }) => {
		const status = requireStatus(keyStorageStatus ?? claims?.key_storage_status, 'key_storage_status');
		const options: WeBuildKeyAttestationOptions = {
			key_storage: ['iso_18045_basic'],
			user_authentication: ['iso_18045_basic'],
			...(issuer === undefined ? {} : { certification: `${issuer.replace(/\/+$/, '')}/api/certification` }),
			...(claims?.key_storage === undefined ? {} : { key_storage: claims.key_storage }),
			...(claims?.user_authentication === undefined ? {} : { user_authentication: claims.user_authentication }),
			...(claims?.certification === undefined ? {} : { certification: claims.certification }),
			...(claims?.status === undefined ? {} : { status: claims.status }),
			key_storage_status: status,
		};
		requireUrl(options.certification);
		return buildKeyAttestationPayload(keys, nonce, options);
	},
	buildWalletAttestationPayload: ({ key, clientId, authorizationServer, attestationId, claims, clientStatus }) => {
		const options: WeBuildWalletInstanceAttestationOptions = {
			wallet_name: 'WE BUILD wwWallet',
			wallet_link: 'https://webuild.wwwallet.org',
			wallet_version: '1.0.0',
			wallet_solution_certification_information: 'WE BUILD Development instance — no wallet solution certification asserted',
			...(claims?.iss === undefined ? {} : { iss: claims.iss }),
			...(claims?.aud === undefined ? {} : { aud: claims.aud }),
			...(claims?.jti === undefined ? {} : { jti: claims.jti }),
			...(claims?.wallet_name === undefined ? {} : { wallet_name: claims.wallet_name }),
			...(claims?.wallet_link === undefined ? {} : { wallet_link: claims.wallet_link }),
			...(claims?.wallet_version === undefined ? {} : { wallet_version: claims.wallet_version as string }),
			...(claims?.wallet_solution_certification_information === undefined
				? {}
				: { wallet_solution_certification_information: claims.wallet_solution_certification_information as string }),
			...(claims?.status === undefined ? {} : { status: claims.status }),
			...(authorizationServer === undefined ? {} : { aud: authorizationServer }),
			...(attestationId === undefined ? {} : { jti: attestationId }),
			client_status: requireStatus(clientStatus ?? (claims?.client_status as KeyStorageStatus | undefined), 'client_status'),
		};
		for (const value of [options.wallet_name, options.wallet_version, options.wallet_solution_certification_information]) {
			if (typeof value !== 'string' || !value.trim()) throw new Error('WEBUILD requires non-empty wallet metadata');
		}
		requireUrl(options.wallet_link);
		return buildWalletAttestationPayload(key, clientId, options);
	},
	getCertificationPage: () =>
		'<!doctype html><html lang="en"><meta charset="utf-8">' +
		'<title>WE BUILD mock wallet certification</title><h1>WE BUILD mock wallet certification</h1>' +
		'<p>Key storage type: keystore. No WSCD certification is asserted.</p>' +
		'<p>No WSCD or keystore certification is asserted. This page is a WE BUILD integration fixture.</p></html>',
};

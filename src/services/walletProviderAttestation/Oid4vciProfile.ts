import { buildWalletAttestationPayload } from '../WalletAttestationService';
import { buildKeyAttestationPayload } from '../KeyAttestationService';
import type { WalletProviderAttestationProfile } from './types';

export const oid4vciProfile: WalletProviderAttestationProfile = {
	id: 'OID4VCI',
	buildKeyAttestationPayload: ({ keys, nonce, claims, keyStorageStatus }) => buildKeyAttestationPayload(keys, nonce, {
		...claims,
		...(keyStorageStatus === undefined ? {} : { status: keyStorageStatus.status }),
	}),
	buildWalletAttestationPayload: ({ key, clientId, issuer, claims, clientStatus }) => {
		if (typeof issuer !== 'string' || issuer.trim().length === 0) {
			throw new Error('OID4VCI wallet attestations require a provider issuer');
		}
		return buildWalletAttestationPayload(key, clientId, {
			...claims,
			iss: issuer,
			...(clientStatus === undefined ? {} : { status: clientStatus.status }),
		});
	},
	getCertificationPage: () => undefined,
};

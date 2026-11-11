import { buildWalletAttestationPayload } from '../WalletAttestationService';
import { buildKeyAttestationPayload } from '../KeyAttestationService';
import type { WalletProviderAttestationProfile } from './types';

export const OpenID4VCIProfile: WalletProviderAttestationProfile = {
	id: 'OPENID4VCI',
	buildKeyAttestationPayload: ({ keys, nonce, claims, keyStorageStatus }) =>
		buildKeyAttestationPayload(keys, nonce, {
			...claims,
			...(keyStorageStatus === undefined ? {} : { status: keyStorageStatus.status }),
		}),
	buildWalletAttestationPayload: ({ key, clientId, issuer, claims, clientStatus }) => {
		if (typeof issuer !== 'string' || issuer.trim().length === 0) {
			throw new Error('OPENID4VCI wallet attestations require a provider issuer');
		}
		return buildWalletAttestationPayload(key, clientId, {
			...claims,
			iss: issuer,
			...(clientStatus === undefined ? {} : { status: clientStatus.status }),
		});
	},
	getCertificationPage: () => undefined,
};

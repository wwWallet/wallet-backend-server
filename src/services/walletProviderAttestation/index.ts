import { OpenID4VCIProfile } from './OpenID4VCIProfile';
import { WeBuildProfile } from './WeBuildProfile';
import type { WalletProviderAttestationProfile, WalletProviderAttestationProfileId } from './types';

const profiles: Record<WalletProviderAttestationProfileId, WalletProviderAttestationProfile> = {
	OPENID4VCI: OpenID4VCIProfile,
	WEBUILD: WeBuildProfile,
};

export function loadWalletProviderAttestationProfile(id: string): WalletProviderAttestationProfile {
	if (!Object.prototype.hasOwnProperty.call(profiles, id)) {
		throw new Error(`Unknown wallet provider attestation profile: ${id}`);
	}
	return profiles[id as WalletProviderAttestationProfileId];
}

export type { WalletProviderAttestationProfile, KeyAttestationInput, WalletProviderAttestationProfileId } from './types';

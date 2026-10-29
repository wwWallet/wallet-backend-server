import { oid4vciProfile } from './Oid4vciProfile';
import { weBuildProfile } from './WeBuildProfile';
import type { WalletProviderAttestationProfile, WalletProviderAttestationProfileId } from './types';

const profiles: Record<WalletProviderAttestationProfileId, WalletProviderAttestationProfile> = {
	OID4VCI: oid4vciProfile,
	WEBUILD: weBuildProfile,
};

export function loadWalletProviderAttestationProfile(id: string): WalletProviderAttestationProfile {
	if (!Object.prototype.hasOwnProperty.call(profiles, id)) {
		throw new Error(`Unknown wallet provider attestation profile: ${id}`);
	}
	return profiles[id as WalletProviderAttestationProfileId];
}

export type { WalletProviderAttestationProfile, KeyAttestationInput, WalletProviderAttestationProfileId } from './types';

import fetch from 'node-fetch';

//const C_MDS_URL = 'https://c-mds.fidoalliance.org/';
const C_MDS_URL = 'http://localhost:8080/';
const COMMUNITY_AAGUID_URL = 'https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/aaguid.json';

type ConvenienceMetadataEntry = {
	friendlyNames?: Record<string, string>;
};

type CommunityMetadataEntry = {
	name: string;
	icon_light?: string;
	icon_dark?: string;
};

let combinedMetadataByAaguid: Record<string, string> = {};
let initialization: Promise<void> | undefined;

export function initializeMetadataService(): Promise<void> {
	if (!initialization) {
		initialization = (async () => {
			const fetchFido = fetch(C_MDS_URL).then(async (res) => {
				if (!res.ok) throw new Error(`C-MDS returned HTTP ${res.status}`);
				return res.json() as Promise<Record<string, ConvenienceMetadataEntry>>;
			});

			const fetchCommunity = fetch(COMMUNITY_AAGUID_URL).then(async (res) => {
				if (!res.ok) throw new Error(`Community MDS returned HTTP ${res.status}`);
				return res.json() as Promise<Record<string, CommunityMetadataEntry>>;
			});

			const [fidoResult, communityResult] = await Promise.allSettled([fetchFido, fetchCommunity]);

			let fidoSuccess = false;
			let communitySuccess = false;

			if (fidoResult.status === 'fulfilled') {
				fidoSuccess = true;
				const fidoData = fidoResult.value;
				for (const [aaguid, entry] of Object.entries(fidoData)) {
					const names = entry.friendlyNames || {};
					const bestName = names['en-US'] || Object.values(names)[0];
					if (bestName) {
						combinedMetadataByAaguid[aaguid.toLowerCase()] = bestName;
					}
				}
			} else {
				console.warn('Could not load FIDO Convenience MDS metadata', fidoResult.reason);
			}

			if (communityResult.status === 'fulfilled') {
				communitySuccess = true;
				const communityData = communityResult.value;
				for (const [aaguid, entry] of Object.entries(communityData)) {
					if (entry.name) {
						combinedMetadataByAaguid[aaguid.toLowerCase()] = entry.name;
					}
				}
			} else {
				console.warn('Could not load Community Passkey metadata', communityResult.reason);
			}

			const totalAuthenticators = Object.keys(combinedMetadataByAaguid).length;

			if (fidoSuccess && communitySuccess) {
				console.log(`[Metadata Service] Fully initialized. Total known authenticators: ${totalAuthenticators}`);
			} else if (fidoSuccess || communitySuccess) {
				console.warn(
					`[Metadata Service] Partially initialized. Total known authenticators: ${totalAuthenticators}. ` +
					`(FIDO: ${fidoSuccess ? 'Success' : 'Failed'}, Community: ${communitySuccess ? 'Success' : 'Failed'})`
				);
			} else {
				console.error(`[Metadata Service] Initialization failed. Both MDS sources could not be fetched.`);
			}
		})();
	}

	return initialization;
}

export async function getAuthenticatorFriendlyName(
	aaguid: string | undefined
): Promise<string | undefined> {
	if (!aaguid) {
		return undefined;
	}

	await initializeMetadataService();
	return combinedMetadataByAaguid[aaguid.toLowerCase()];
}

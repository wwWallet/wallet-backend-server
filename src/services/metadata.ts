import fetch, { Response } from 'node-fetch';
import { config } from '../../config';
import { readFile } from 'fs/promises';
import path from 'path';

type ConvenienceMetadataEntry = {
	friendlyNames?: Record<string, string>;
};

type CommunityMetadataEntry = {
	name: string;
	icon_light?: string;
	icon_dark?: string;
};

type MetadataCache<T> = {
	data: T;
	etag?: string;
	fetchedAt?: number;
	inFlight?: Promise<void>;
};

const fidoMetadata: MetadataCache<Record<string, ConvenienceMetadataEntry>> = { data: {} };
const communityMetadata: MetadataCache<Record<string, CommunityMetadataEntry>> = { data: {} };

let combinedMetadataByAaguid: Record<string, string> = {};
let initialization: Promise<void> | undefined;

function isStale(cache: MetadataCache<unknown>): boolean {
	return cache.fetchedAt === undefined || Date.now() - cache.fetchedAt >= config.metadata.refreshIntervalMs;
}

function conditionalRequest(url: string, etag?: string): Promise<Response> {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), 5000);

	const headers: Record<string, string> = {};
	if (etag) {
		headers['If-None-Match'] = etag;
	}

	return fetch(url, {
		headers,
		signal: controller.signal as any
	}).finally(() => {
		clearTimeout(timeoutId);
	});
}

function rebuildCombinedMetadata(): void {
	const combined: Record<string, string> = {};

	for (const [aaguid, entry] of Object.entries(fidoMetadata.data)) {
		const names = entry.friendlyNames || {};
		const bestName = names['en-US'] || Object.values(names)[0];
		if (bestName) combined[aaguid.toLowerCase()] = bestName;
	}

	for (const [aaguid, entry] of Object.entries(communityMetadata.data)) {
		if (entry.name) combined[aaguid.toLowerCase()] = entry.name;
	}

	combinedMetadataByAaguid = combined;
}

async function refreshCache<T>(
	cache: MetadataCache<T>,
	url: string,
	sourceName: string,
	fallbackFilePath: string
): Promise<void> {
	if (!isStale(cache)) return;
	if (cache.inFlight) return cache.inFlight;

	cache.inFlight = (async () => {
		let networkSuccess = false;

		try {
			const response = await conditionalRequest(url, cache.etag);
			if (response.status === 304) {
				cache.fetchedAt = Date.now();
				return;
			}
			if (!response.ok) throw new Error(`${sourceName} returned HTTP ${response.status}`);

			cache.data = await response.json() as T;
			cache.etag = response.headers.get('etag') || undefined;
			cache.fetchedAt = Date.now();
			networkSuccess = true;
		} catch (error) {
			console.warn(`[Metadata Service] Could not load ${sourceName} from network:`, (error as Error).message);
		}

		if (!networkSuccess && Object.keys(cache.data as Record<string, unknown>).length === 0) {
			try {
				console.log(`[Metadata Service] Attempting to load ${sourceName} from local fallback...`);
				const fileContent = await readFile(fallbackFilePath, 'utf-8');
				cache.data = JSON.parse(fileContent) as T;
				cache.fetchedAt = Date.now();
				console.log(`[Metadata Service] Successfully loaded ${sourceName} from fallback.`);
			} catch (fallbackError) {
				console.error(`[Metadata Service] Failed to load ${sourceName} from local fallback:`, (fallbackError as Error).message);
			}
		}

		rebuildCombinedMetadata();
	})().finally(() => {
		cache.inFlight = undefined;
	});

	return cache.inFlight;
}

export function fetchFido(): Promise<void> {
	const fallbackPath = path.join(process.cwd(), 'src/metadata/convenience-metadata.json');
	return refreshCache(fidoMetadata, config.metadata.fidoUrl, 'FIDO Convenience MDS', fallbackPath);
}

export function fetchCommunity(): Promise<void> {
	const fallbackPath = path.join(process.cwd(), 'src/metadata/aaguid.json');
	return refreshCache(communityMetadata, config.metadata.communityAaguidUrl, 'Community Passkey MDS', fallbackPath);
}

export function initializeMetadataService(): Promise<void> {
	if (initialization) return initialization;

	initialization = (async () => {
		await Promise.all([fetchFido(), fetchCommunity()]);

		const fidoSuccess = fidoMetadata.fetchedAt !== undefined;
		const communitySuccess = communityMetadata.fetchedAt !== undefined;
		const totalAuthenticators = Object.keys(combinedMetadataByAaguid).length;

		if (fidoSuccess && communitySuccess) {
			console.log(`[Metadata Service] Initialized. Total known authenticators: ${totalAuthenticators}`);
		} else if (fidoSuccess || communitySuccess) {
			console.warn(
				`[Metadata Service] Partially initialized. Total known authenticators: ${totalAuthenticators}. ` +
				`(FIDO: ${fidoSuccess ? 'Success' : 'Failed'}, Community: ${communitySuccess ? 'Success' : 'Failed'})`
			);
		} else {
			console.error('[Metadata Service] Initialization failed. Both MDS sources could not be fetched and fallbacks failed.');
		}
	})().finally(() => {
		initialization = undefined;
	});

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

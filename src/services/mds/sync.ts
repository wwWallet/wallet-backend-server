import { promises as fs } from 'fs';
import config from './config';
import * as cache from './cache';
import * as mds from './mds';

async function triggerStaleMdsAlert(daysStale: number | string): Promise<void> {
	const msg = `CRITICAL: FIDO MDS Blob is ${daysStale} days past its update deadline.`;
	console.error(msg);
	await fs.appendFile(config.paths.errorLog, `[${new Date().toISOString()}] ${msg}\n`, 'utf8');
}

async function fetchAndProcessBlob(): Promise<void> {
	console.log("Fetching FIDO MDS Blob...");
	const response = await fetch(config.urls.fidoMds);
	if (!response.ok) throw new Error(`HTTP ${response.status}`);

	const rawBlob = await response.text();
	await mds.validateBlobAuthenticity(rawBlob);

	const { payloadMap, nextUpdate } = mds.parseAndFormatBlob(rawBlob);
	await cache.saveToDisk(rawBlob, payloadMap, nextUpdate);
	console.log(`MDS Cache updated. Next update: ${nextUpdate}`);
}

export async function executeFidoSync(): Promise<void> {
	console.log("Starting Sync...");

	if (!cache.memoryCache.data) {
		const localBlob = await cache.loadFromDisk();
		if (localBlob) {
			const { payloadMap, nextUpdate } = mds.parseAndFormatBlob(localBlob);
			cache.memoryCache.data = payloadMap;
			cache.memoryCache.nextUpdate = new Date(nextUpdate).getTime();
			console.log("Loaded from local disk.");
		}
	}

	const now = Date.now();
	if (!cache.memoryCache.data || now >= cache.memoryCache.nextUpdate) {
		try {
			await fetchAndProcessBlob();
		} catch (error: any) {
			console.error("Fetch/Validation failed:", error.message);
		}
	} else {
		console.log("Local MDS blob is still fresh.");
	}

	if (cache.memoryCache.nextUpdate) {
		const staleTime = now - cache.memoryCache.nextUpdate;
		if (staleTime > config.thresholds.staleMs) {
			const daysStale = (staleTime / (1000 * 60 * 60 * 24)).toFixed(1);
			await triggerStaleMdsAlert(daysStale);
		}
	} else {
		await triggerStaleMdsAlert("unknown (cache empty)");
	}
}

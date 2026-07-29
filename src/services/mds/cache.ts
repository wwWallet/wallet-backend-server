import { promises as fs } from 'fs';
import config from './config';

export const memoryCache: { data: any, nonFidoData: any, nextUpdate: number } = {
	data: null,
	nonFidoData: null,
	nextUpdate: 0
};

export async function saveToDisk(rawBlob: string, payloadMap: any, nextUpdate: string) {
	memoryCache.data = payloadMap;
	memoryCache.nextUpdate = new Date(nextUpdate).getTime();

	await fs.writeFile(config.paths.cacheJson, JSON.stringify(memoryCache.data, null, 3), 'utf8');
	await fs.writeFile(config.paths.blob, rawBlob, 'utf8');
}

export async function loadNonFidoMDS() {
	try {
		const rawData = await fs.readFile(config.paths.cacheNonFidoMDS, 'utf8');
		memoryCache.nonFidoData = JSON.parse(rawData);
		console.log("Loaded static non-FIDO MDS data.");
	} catch (err: any) {
		console.warn("Could not load cache-non-fido-mds.json. Proceeding without custom entries.", err.message);
		memoryCache.nonFidoData = {};
	}
}

export async function loadFromDisk() {
	try {
		return await fs.readFile(config.paths.blob, 'utf8');
	} catch (err) {
		return null;
	}
}

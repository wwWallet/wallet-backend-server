import { promises as fs } from 'fs';
import config from './config';

export const memoryCache: { data: any, nextUpdate: number } = { data: null, nextUpdate: 0 };

export async function saveToDisk(rawBlob: string, payloadMap: any, nextUpdate: string) {
	memoryCache.data = payloadMap;
	memoryCache.nextUpdate = new Date(nextUpdate).getTime();

	await fs.writeFile(config.paths.cacheJson, JSON.stringify(memoryCache.data, null, 2), 'utf8');
	await fs.writeFile(config.paths.blob, rawBlob, 'utf8');
}

export async function loadFromDisk() {
	try {
		return await fs.readFile(config.paths.blob, 'utf8');
	} catch (err) {
		return null;
	}
}
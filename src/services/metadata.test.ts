import fetch, { Response } from 'node-fetch';
import { readFile } from 'fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('node-fetch', async (importOriginal) => ({
	...(await importOriginal<typeof import('node-fetch')>()),
	default: vi.fn(),
}));
vi.mock('fs/promises', () => ({ readFile: vi.fn() }));
vi.mock('../../config', () => ({
	config: {
		metadata: {
			fidoUrl: 'https://fido.invalid/metadata',
			communityAaguidUrl: 'https://community.invalid/metadata',
			refreshIntervalMs: 604800000,
		},
	},
}));

const sharedAaguid = '00112233-4455-6677-8899-aabbccddeeff';
const fidoOnlyAaguid = '11223344-5566-7788-99aa-bbccddeeff00';
const communityOnlyAaguid = '22334455-6677-8899-aabb-ccddeeff0011';
const unnamedAaguid = '33445566-7788-99aa-bbcc-ddeeff001122';
const refreshIntervalMs = 604800000;
let fidoBody: Record<string, unknown>;
let communityBody: Record<string, unknown>;
let metadata: typeof import('./metadata');

beforeEach(async () => {
	vi.useFakeTimers();
	vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
	vi.resetModules();
	vi.mocked(fetch).mockReset();
	vi.mocked(readFile).mockReset();
	vi.mocked(readFile).mockRejectedValue(new Error('No fallback available'));
	fidoBody = {
		[sharedAaguid]: { friendlyNames: { 'en-US': 'FIDO name' } },
		[fidoOnlyAaguid]: { friendlyNames: { fr: 'Nom français', 'en-US': 'English name' } },
		[unnamedAaguid]: {},
	};
	communityBody = {
		[sharedAaguid.toUpperCase()]: { name: 'Community name' },
		[communityOnlyAaguid]: { name: 'Community-only name' },
	};
	vi.mocked(fetch).mockImplementation(async (url) => {
		if (url === 'https://fido.invalid/metadata') {
			return new Response(JSON.stringify(fidoBody), { headers: { ETag: '"fido-v1"' } });
		}
		if (url === 'https://community.invalid/metadata') {
			return new Response(JSON.stringify(communityBody), { headers: { ETag: '"community-v1"' } });
		}
		throw new Error(`Unexpected metadata URL: ${url}`);
	});
	metadata = await import('./metadata');
});

afterEach(() => {
	vi.useRealTimers();
});

describe('authenticator friendly names', () => {
	it('prefers the community name when both sources describe the same AAGUID', async () => {
		expect(await metadata.getAuthenticatorFriendlyName(sharedAaguid)).toBe('Community name');
	});

	it('matches AAGUIDs case-insensitively in both sources', async () => {
		expect(await metadata.getAuthenticatorFriendlyName(fidoOnlyAaguid.toUpperCase())).toBe('English name');
		expect(await metadata.getAuthenticatorFriendlyName(communityOnlyAaguid.toUpperCase())).toBe('Community-only name');
	});

	it('prefers an English FIDO name even when another language appears first', async () => {
		expect(await metadata.getAuthenticatorFriendlyName(fidoOnlyAaguid)).toBe('English name');
	});

	it('uses another language when the FIDO entry has no English name', async () => {
		fidoBody[fidoOnlyAaguid] = { friendlyNames: { fr: 'Nom français' } };
		expect(await metadata.getAuthenticatorFriendlyName(fidoOnlyAaguid)).toBe('Nom français');
	});

	it('returns undefined for a missing AAGUID without fetching metadata', async () => {
		expect(await metadata.getAuthenticatorFriendlyName(undefined)).toBeUndefined();
		expect(fetch).not.toHaveBeenCalled();
	});

	it('returns undefined for an unknown AAGUID after loading metadata', async () => {
		expect(await metadata.getAuthenticatorFriendlyName('44556677-8899-aabb-ccdd-eeff00112233')).toBeUndefined();
		expect(fetch).toHaveBeenCalledTimes(2);
	});
});

describe('metadata caching and failures', () => {
	it('returns undefined for an entry without a friendly name', async () => {
		expect(await metadata.getAuthenticatorFriendlyName(unnamedAaguid)).toBeUndefined();
	});

	it('shares concurrent initialization and reuses fresh metadata', async () => {
		const initialization = metadata.initializeMetadataService();
		expect(metadata.initializeMetadataService()).toBe(initialization);
		await Promise.all([
			initialization,
			metadata.getAuthenticatorFriendlyName(sharedAaguid),
			metadata.fetchFido(),
			metadata.fetchCommunity(),
		]);
		expect(await metadata.getAuthenticatorFriendlyName(sharedAaguid)).toBe('Community name');
		expect(fetch).toHaveBeenCalledTimes(2);
		expect(readFile).not.toHaveBeenCalled();
	});

	it('revalidates stale metadata with source-specific ETags and retains names on 304', async () => {
		await metadata.initializeMetadataService();
		vi.setSystemTime(Date.now() + refreshIntervalMs);
		vi.mocked(fetch).mockClear();
		vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 304 }));
		expect(await metadata.getAuthenticatorFriendlyName(sharedAaguid)).toBe('Community name');
		for (const [source, etag] of [
			['fido', 'fido-v1'],
			['community', 'community-v1'],
		]) {
			expect(fetch).toHaveBeenCalledWith(
				`https://${source}.invalid/metadata`,
				expect.objectContaining({
					headers: { 'If-None-Match': `"${etag}"` },
				}),
			);
		}
		await metadata.initializeMetadataService();
		expect(fetch).toHaveBeenCalledTimes(2);
		expect(readFile).not.toHaveBeenCalled();
	});

	it('replaces stale metadata after successful refresh', async () => {
		await metadata.initializeMetadataService();
		communityBody = { [communityOnlyAaguid]: { name: 'Updated name' } };
		vi.setSystemTime(Date.now() + refreshIntervalMs);
		expect(await metadata.getAuthenticatorFriendlyName(communityOnlyAaguid)).toBe('Updated name');
		expect(await metadata.getAuthenticatorFriendlyName(sharedAaguid)).toBe('FIDO name');
	});

	it.each(['HTTP failure', 'invalid payload', 'connection failure'])('loads validated fallback data after %s', async (failure) => {
		if (failure === 'connection failure') {
			vi.mocked(fetch).mockRejectedValue(new Error('Connection refused'));
		} else {
			vi.mocked(fetch).mockImplementation(async () =>
				failure === 'HTTP failure'
					? new Response(null, { status: 503 })
					: new Response(JSON.stringify({ invalid: { friendlyNames: 123, name: 123 } })),
			);
		}
		vi.mocked(readFile).mockImplementation(async (file) => {
			if (file === path.join(process.cwd(), 'resources/metadata/convenience-metadata.json')) {
				return JSON.stringify({ [fidoOnlyAaguid]: { friendlyNames: { 'en-US': 'Fallback FIDO' } } });
			}
			if (file === path.join(process.cwd(), 'resources/metadata/aaguid.json')) {
				return JSON.stringify({ [communityOnlyAaguid]: { name: 'Fallback community' } });
			}
			throw new Error(`Unexpected fallback path: ${file}`);
		});
		expect(await metadata.getAuthenticatorFriendlyName(fidoOnlyAaguid)).toBe('Fallback FIDO');
		expect(await metadata.getAuthenticatorFriendlyName(communityOnlyAaguid)).toBe('Fallback community');
		expect(fetch).toHaveBeenCalledTimes(2);
		expect(readFile).toHaveBeenCalledTimes(2);
	});

	it('retains cached data after refresh failure and retries only after backoff expires', async () => {
		await metadata.initializeMetadataService();
		vi.setSystemTime(Date.now() + refreshIntervalMs);
		vi.mocked(fetch).mockRejectedValue(new Error('Connection refused'));
		expect(await metadata.getAuthenticatorFriendlyName(sharedAaguid)).toBe('Community name');
		const backoffMs = 24 * 60 * 60 * 1000;
		vi.setSystemTime(Date.now() + backoffMs - 1);
		await metadata.initializeMetadataService();
		expect(fetch).toHaveBeenCalledTimes(4);
		vi.setSystemTime(Date.now() + 1);
		expect(await metadata.getAuthenticatorFriendlyName(sharedAaguid)).toBe('Community name');
		expect(fetch).toHaveBeenCalledTimes(6);
		expect(readFile).not.toHaveBeenCalled();
	});

	it.each(['missing', 'malformed JSON', 'invalid schema'])('returns no name when both sources and %s fallbacks fail', async (fallback) => {
		vi.mocked(fetch).mockRejectedValue(new Error('Connection refused'));
		if (fallback !== 'missing') {
			vi.mocked(readFile).mockResolvedValue(fallback === 'malformed JSON' ? '{' : '{}');
		}
		expect(await metadata.getAuthenticatorFriendlyName(sharedAaguid)).toBeUndefined();
		expect(readFile).toHaveBeenCalledTimes(2);
	});

	it('uses the available source when the other source and its fallback fail', async () => {
		communityBody = {};
		expect(await metadata.getAuthenticatorFriendlyName(sharedAaguid)).toBe('FIDO name');
		expect(readFile).toHaveBeenCalledTimes(1);
		expect(readFile).toHaveBeenCalledWith(path.join(process.cwd(), 'resources/metadata/aaguid.json'), 'utf-8');
	});
});

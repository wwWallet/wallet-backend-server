import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { testEnv } from './test-environment';

describe('config', () => {
	const originalCwd = process.cwd();
	const originalEnv = process.env;
	const validEnv = testEnv;
	let directory: string;

	beforeAll(() => {
		directory = mkdtempSync(path.join(tmpdir(), 'backend-config-'));
	});

	beforeEach(() => {
		// Load real dotenv from a disposable directory, never the developer's .env.
		process.chdir(directory);
		process.env = { ...validEnv };
		vi.resetModules();
	});

	afterEach(() => {
		// Hooks restore state even when an import or assertion fails.
		process.env = originalEnv;
		process.chdir(originalCwd);
		vi.resetModules();
		rmSync(path.join(directory, '.env'), { force: true });
	});

	afterAll(() => {
		if (directory) rmSync(directory, { recursive: true, force: true });
	});

	async function importConfig() {
		return (await import('.')).config;
	}

	it('defaults to OID4VCI', async () => {
		expect((await importConfig()).walletProviderAttestationProfile).toBe('OID4VCI');
	});

	it.each(['OID4VCI', 'WEBUILD'])('selects profile %s', async (profile) => {
		process.env.WALLET_PROVIDER_ATTESTATION_PROFILE = profile;
		expect((await importConfig()).walletProviderAttestationProfile).toBe(profile);
	});

	it('rejects unknown profiles at startup', async () => {
		process.env.WALLET_PROVIDER_ATTESTATION_PROFILE = 'typo';
		await expect(importConfig()).rejects.toThrow('WALLET_PROVIDER_ATTESTATION_PROFILE');
	});

	it('reads required settings and converts numeric ports', async () => {
		const config = await importConfig();
		expect(config.port).toBe(8002);
		expect(config.appSecret).toBe(validEnv.APP_SECRET);
		expect(config.db).toEqual({
			host: 'database.invalid',
			port: 3306,
			username: 'unit-test',
			password: 'synthetic-password',
			dbname: 'unit-test',
		});
		expect(config.webauthn).toEqual({
			attestation: 'direct',
			origin: ['https://wallet.example'],
			rp: {
				id: 'wallet.example',
				name: 'wwWallet demo',
			},
		});
	});

	it('uses the documented optional defaults', async () => {
		const config = await importConfig();
		expect(config.url).toBe('http://localhost:8002');
		expect(config.keysDir).toBe('/app/keys');
		expect(config.ohttpGatewayUrl).toBe('http://localhost:4567');
		expect(config.metadata).toEqual({
			fidoUrl: 'https://c-mds.fidoalliance.org',
			communityAaguidUrl: 'https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/aaguid.json',
			refreshIntervalMs: 604800000,
		});
		expect(config.registerDisabled).toBe(false);
		expect(config.debugAcceptUnauthorizedHttps).toBe(false);
	});

	it('reads explicit optional settings', async () => {
		Object.assign(process.env, {
			APP_URL: 'https://backend.example',
			KEYS_DIR: '/synthetic/keys',
			WEBAUTHN_RP_NAME: 'Test wallet',
			OHTTP_GATEWAY_URL: 'http://gateway.invalid',
			METADATA_FIDO_URL: 'https://fido.invalid',
			METADATA_COMMUNITY_AAGUID_URL: 'https://community.invalid',
			METADATA_REFRESH_INTERVAL_MS: '1234',
		});
		const config = await importConfig();
		expect(config.url).toBe('https://backend.example');
		expect(config.keysDir).toBe('/synthetic/keys');
		expect(config.webauthn.rp.name).toBe('Test wallet');
		expect(config.ohttpGatewayUrl).toBe('http://gateway.invalid');
		expect(config.metadata).toEqual({
			fidoUrl: 'https://fido.invalid',
			communityAaguidUrl: 'https://community.invalid',
			refreshIntervalMs: 1234,
		});
	});

	it('splits and trims multiple WebAuthn origins, ignoring empty entries', async () => {
		process.env.WEBAUTHN_ORIGIN = ' https://one.example, , https://two.example , ';
		expect((await importConfig()).webauthn.origin).toEqual(['https://one.example', 'https://two.example']);
	});

	it.each(['true', 'TRUE', 'TrUe'])('enables flags for case-insensitive true (%s)', async (value) => {
		process.env.REGISTRATION_DISABLED = value;
		process.env.DEBUG_ACCEPT_UNAUTHORIZED_HTTPS = value;
		const config = await importConfig();
		expect(config.registerDisabled).toBe(true);
		expect(config.debugAcceptUnauthorizedHttps).toBe(true);
	});

	it('keeps explicitly false flags disabled', async () => {
		process.env.REGISTRATION_DISABLED = 'false';
		process.env.DEBUG_ACCEPT_UNAUTHORIZED_HTTPS = 'false';
		const config = await importConfig();
		expect(config.registerDisabled).toBe(false);
		expect(config.debugAcceptUnauthorizedHttps).toBe(false);
	});

	const requiredSettings = [
		'PORT',
		'APP_SECRET',
		'DB_HOST',
		'DB_PORT',
		'DB_USER',
		'DB_PASSWORD',
		'DB_NAME',
		'WEBAUTHN_ORIGIN',
		'WEBAUTHN_RP_ID',
	];
	it.each(requiredSettings)('rejects missing required setting %s', async (name) => {
		delete process.env[name];
		await expect(importConfig()).rejects.toThrow(`- ${name} is required`);
	});

	it('treats an empty required value as unset', async () => {
		process.env.APP_SECRET = '';
		await expect(importConfig()).rejects.toThrow('- APP_SECRET is required');
	});

	it.each(['0', '65536', '-1', '8002suffix', '1.5'])('rejects invalid port %j', async (value) => {
		process.env.PORT = value;
		process.env.DB_PORT = value;
		await expect(importConfig()).rejects.toThrow('- PORT must be a port number');
		await expect(importConfig()).rejects.toThrow('- DB_PORT must be a port number');
	});

	it('accepts the minimum and maximum port values', async () => {
		process.env.PORT = '1';
		process.env.DB_PORT = '65535';
		const config = await importConfig();
		expect(config.port).toBe(1);
		expect(config.db.port).toBe(65535);
	});

	it.each(['0', '-1', 'invalid', ''])('uses the metadata refresh default for %j', async (value) => {
		process.env.METADATA_REFRESH_INTERVAL_MS = value;
		expect((await importConfig()).metadata.refreshIntervalMs).toBe(604800000);
	});

	it('rejects the unresolved signing-secret placeholder', async () => {
		process.env.APP_SECRET = '${SERVICE_SECRET}';
		await expect(importConfig()).rejects.toThrow('must not be the template placeholder');
	});

	it('rejects the development signing secret in production', async () => {
		process.env.NODE_ENV = 'production';
		process.env.APP_SECRET = 'dev-only-insecure-secret';
		await expect(importConfig()).rejects.toThrow('must not be the .env.template value in production');
	});

	it('accepts a separate signing secret in production', async () => {
		process.env.NODE_ENV = 'production';
		expect((await importConfig()).appSecret).toBe(testEnv.APP_SECRET);
	});

	it('accepts the template signing secret in development', async () => {
		process.env.NODE_ENV = 'development';
		process.env.APP_SECRET = 'dev-only-insecure-secret';
		expect((await importConfig()).appSecret).toBe('dev-only-insecure-secret');
	});

	it('reports invalid settings without exposing configured secrets', async () => {
		process.env.PORT = 'invalid';
		await expect(importConfig()).rejects.toThrow('Invalid wallet-backend-server configuration');
		await expect(importConfig()).rejects.not.toThrow(testEnv.APP_SECRET);
		await expect(importConfig()).rejects.not.toThrow(testEnv.DB_PASSWORD);
	});

	it('loads a real .env file while giving environment variables precedence', async () => {
		writeFileSync(path.join(directory, '.env'), 'APP_URL=https://from-file.example\nPORT=9000\nWEBAUTHN_RP_NAME=From file\n');
		const config = await importConfig();
		expect(config.url).toBe('https://from-file.example');
		expect(config.port).toBe(8002);
		expect(config.webauthn.rp.name).toBe('From file');
	});

	it('detects unsafe environment prefixes even when their values are empty or false', async () => {
		Object.assign(process.env, {
			DEBUG_TLS: 'false',
			DEV_FEATURE: '',
			UNSAFE_MODE: '0',
			INSECURE_HTTP: 'true',
		});
		const { getUnsafeEnvironmentVariables } = await import('../src/configValidation');
		expect(getUnsafeEnvironmentVariables().sort()).toEqual(['DEBUG_TLS', 'DEV_FEATURE', 'INSECURE_HTTP', 'UNSAFE_MODE']);
	});

	it('does not match safe names that merely contain an unsafe word', async () => {
		Object.assign(process.env, {
			LOG_DEBUG: 'true',
			DEVELOPMENT: 'true',
			NODE_ENV: 'development',
		});
		const { getUnsafeEnvironmentVariables } = await import('../src/configValidation');
		expect(getUnsafeEnvironmentVariables()).toEqual([]);
	});
});

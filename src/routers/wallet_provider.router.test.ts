import { generateKeyPairSync } from 'node:crypto';
import type { Request, Response } from 'express';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
	allocate: vi.fn(),
	load: vi.fn(),
	sign: vi.fn(),
	status: vi.fn(),
	signStatus: vi.fn(),
	profile: 'OPENID4VCI',
}));
vi.mock('../../config', () => ({
	config: {
		url: 'https://provider.example/',
		get walletProviderAttestationProfile() {
			return mocks.profile;
		},
	},
}));
vi.mock('../middlewares/auth.middleware', () => ({ AuthMiddleware: vi.fn() }));
vi.mock('../logger', () => ({ logger: { child: () => ({ error: vi.fn(), warn: vi.fn() }) } }));
vi.mock('../entities/WalletProviderStatus.entity', () => ({
	allocateWalletProviderStatus: mocks.allocate,
	revokeWalletProviderStatusesForAccount: vi.fn(),
	getWalletProviderStatusList: mocks.status,
	WalletProviderStatusErr: { NOT_EXISTS: 'NOT_EXISTS' },
	STATUS_TOKEN_SECONDS: 60,
}));
vi.mock('../services/WalletProviderService', () => ({
	loadWalletProviderSigningMaterial: mocks.load,
	signWalletProviderAttestation: mocks.sign,
	buildWalletProviderStatusClaim: () => ({ status: { status_list: { idx: 1, uri: 'https://provider.example/status' } }, exp: 2000000000 }),
	signWalletProviderStatusList: mocks.signStatus,
}));

const publicKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
const routes = ['/key-attestation/generate', '/wallet-attestation/generate'];

async function request(path: string, jwks: unknown, authenticated = true) {
	const { walletProviderRouter } = await import('./wallet_provider.router');
	const route = walletProviderRouter.stack.find((layer) => layer.route?.path === path)?.route;
	if (!route || route.stack.length === 0) {
		throw new Error(`Missing test route: ${path}`);
	}
	const res = { status: vi.fn().mockReturnThis(), send: vi.fn().mockReturnThis() };
	const req = {
		user: authenticated ? { id: { id: 'account' } } : undefined,
		body: { jwks, openid4vci: { nonce: 'nonce', client_id: 'client', authorization_server: 'https://as.example' } },
	};
	const next = vi.fn();
	// Invoke the authenticated handler with the request/response fields exercised by these tests.
	await route.stack[route.stack.length - 1].handle(req as unknown as Request, res as unknown as Response, next);
	expect(next).not.toHaveBeenCalled();
	return res;
}

beforeEach(() => {
	vi.clearAllMocks();
	vi.resetModules();
	mocks.profile = 'OPENID4VCI';
	mocks.allocate.mockResolvedValue({ ok: true, val: { id: 'allocated-id' } });
	mocks.load.mockResolvedValue({});
	mocks.sign.mockResolvedValue('signed-attestation');
});

describe('wallet provider public key validation', () => {
	it.each(routes)('rejects a missing authenticated user before allocation on %s', async (path) => {
		const res = await request(path, [publicKey], false);
		expect(res.status).toHaveBeenCalledWith(401);
		expect(mocks.allocate).not.toHaveBeenCalled();
		expect(mocks.sign).not.toHaveBeenCalled();
	});
	it.each(routes)('validates keys before signing on %s', async (path) => {
		const res = await request(path, [publicKey]);
		expect(res.send).toHaveBeenCalledWith(
			path === routes[0] ? { key_attestation: 'signed-attestation' } : { wallet_instance_attestation: 'signed-attestation' },
		);
		expect(mocks.sign).toHaveBeenCalledOnce();
		expect(mocks.allocate).toHaveBeenCalledWith('account', path === routes[0] ? 'ka' : 'wa');
		const payload = mocks.sign.mock.calls[0][0];
		const expectedPayload =
			path === routes[0] ? { attested_keys: [publicKey] } : { cnf: { jwk: publicKey }, iss: 'https://provider.example/wallet-provider' };
		expect(payload).toMatchObject(expectedPayload);
	});
	it.each(routes)('rejects private keys before allocation on %s', async (path) => {
		const res = await request(path, [{ ...publicKey, d: 'secret' }]);
		expect(res.status).toHaveBeenCalledWith(400);
		expect(mocks.allocate).not.toHaveBeenCalled();
		expect(mocks.sign).not.toHaveBeenCalled();
	});
	it('validates every key in a batch', async () => {
		const res = await request(routes[0], [publicKey, { kty: 'oct', k: 'secret' }]);
		expect(res.status).toHaveBeenCalledWith(400);
		expect(mocks.sign).not.toHaveBeenCalled();
	});
	it('rejects multiple wallet-instance keys', async () => {
		const res = await request(routes[1], [publicKey, publicKey]);
		expect(res.status).toHaveBeenCalledWith(400);
		expect(mocks.sign).not.toHaveBeenCalled();
	});
});

describe('WEBUILD lifecycle payloads', () => {
	it.each(routes)('generates complete WEBUILD claims on %s', async (path) => {
		mocks.profile = 'WEBUILD';
		const res = await request(path, [publicKey]);
		expect(res.status).not.toHaveBeenCalled();
		expect(mocks.sign).toHaveBeenCalledOnce();
		const payload = mocks.sign.mock.calls[0][0];
		const expectedPayload =
			path === routes[0]
				? {
						attested_keys: [publicKey],
						nonce: 'nonce',
						key_storage: ['iso_18045_basic'],
						user_authentication: ['iso_18045_basic'],
						certification: 'https://provider.example/wallet-provider/api/certification',
						key_storage_status: { status: { status_list: { idx: 1 } }, exp: 2000000000 },
					}
				: {
						jti: 'allocated-id',
						sub: 'client',
						aud: 'https://as.example',
						cnf: { jwk: publicKey },
						wallet_name: 'WE BUILD wwWallet',
						wallet_link: 'https://webuild.wwwallet.org',
						wallet_version: '1.0.0',
						wallet_solution_certification_information: 'WE BUILD Development instance — no wallet solution certification asserted',
						client_status: { status: { status_list: { idx: 1 } }, exp: 2000000000 },
					};
		expect(payload).toMatchObject(expectedPayload);
	});
});

describe('weekly status list URLs', () => {
	async function fetchStatus(id: string) {
		const { walletProviderPublicRouter } = await import('./wallet_provider.router');
		const route = walletProviderPublicRouter.stack.find((layer) => layer.route?.path === '/status-lists/:statusListId')?.route;
		if (!route) throw new Error('Missing status route');
		const res = {
			status: vi.fn().mockReturnThis(),
			json: vi.fn().mockReturnThis(),
			set: vi.fn().mockReturnThis(),
			type: vi.fn().mockReturnThis(),
			send: vi.fn().mockReturnThis(),
		};
		await route.stack[0].handle(
			{ params: { statusListId: id }, query: {}, accepts: () => true } as unknown as Request,
			res as unknown as Response,
			vi.fn(),
		);
		return res;
	}

	it('publishes the new hash ID with its exact subject and freshness', async () => {
		const id = '-IvkJWcUf6xBjy8wBMe5E0YwbbSBOtKB7R1-wX-s3b0';
		mocks.status.mockResolvedValue({ ok: true, val: { bits: 1, lst: 'compressed' } });
		mocks.signStatus.mockResolvedValue('signed-status');
		const res = await fetchStatus(id);
		expect(res.status).toHaveBeenCalledWith(200);
		expect(res.send).toHaveBeenCalledWith('signed-status');
		expect(mocks.status).toHaveBeenCalledWith(id);
		const jwt = mocks.signStatus.mock.calls[0][0];
		expect(jwt._payload).toMatchObject({ sub: `https://provider.example/wallet-provider/api/status-lists/${id}`, ttl: 60 });
		expect(jwt._payload.exp - jwt._payload.iat).toBe(60);
	});

	it.each(['v2_' + 'a'.repeat(43), 'v1_short', '00000000-0000-4000-8000-000000000000'])('rejects unsupported ID %s', async (id) => {
		const res = await fetchStatus(id);
		expect(res.status).toHaveBeenCalledWith(404);
		expect(mocks.status).not.toHaveBeenCalled();
	});

	it('returns 404 for an unknown hash', async () => {
		mocks.status.mockResolvedValue({ ok: false, val: 'NOT_EXISTS' });
		expect((await fetchStatus('a'.repeat(43))).status).toHaveBeenCalledWith(404);
	});
});

it('serves the WEBUILD certification page through the public router', async () => {
	mocks.profile = 'WEBUILD';
	const { walletProviderPublicRouter } = await import('./wallet_provider.router');
	const route = walletProviderPublicRouter.stack.find((layer) => layer.route?.path === '/certification')?.route;
	if (!route) throw new Error('Missing certification route');
	const res = { type: vi.fn().mockReturnThis(), send: vi.fn().mockReturnThis() };
	await route.stack[0].handle({} as Request, res as unknown as Response, vi.fn());
	expect(res.type).toHaveBeenCalledWith('html');
	expect(res.send).toHaveBeenCalledWith(expect.stringContaining('WE BUILD mock wallet certification'));
});

import { generateKeyPairSync } from 'node:crypto';
import type { Request, Response } from 'express';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ allocate: vi.fn(), load: vi.fn(), sign: vi.fn(), profile: 'OID4VCI' }));
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
	revokeWalletProviderStatus: vi.fn(),
	getWalletProviderStatusList: vi.fn(),
	WalletProviderStatusErr: {},
	STATUS_TOKEN_SECONDS: 300,
}));
vi.mock('../services/WalletProviderService', () => ({
	loadWalletProviderSigningMaterial: mocks.load,
	signWalletProviderAttestation: mocks.sign,
	buildWalletProviderStatusClaim: () => ({ status: { status_list: { idx: 1, uri: 'https://provider.example/status' } }, exp: 2000000000 }),
	signWalletProviderStatus: vi.fn(),
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
	mocks.profile = 'OID4VCI';
	mocks.allocate.mockResolvedValue({ ok: true, val: { id: 'allocated-id' } });
	mocks.load.mockResolvedValue({});
	mocks.sign.mockResolvedValue('signed-attestation');
});

describe('wallet provider public key validation', () => {
	it.each(routes)('rejects a missing authenticated user before allocation on %s', async (path) => {
		const res = await request(path, [publicKey], false);
		expect(res.status).toHaveBeenCalledWith(401);
		expect(mocks.load).not.toHaveBeenCalled();
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
		expect(mocks.load).not.toHaveBeenCalled();
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
						certification: 'https://provider.example/wallet-provider/certification',
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

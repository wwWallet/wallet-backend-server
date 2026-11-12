import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ readFileSync: vi.fn(), importKey: vi.fn(), chain: vi.fn(), sign: vi.fn() }));
vi.mock('fs', () => ({ readFileSync: mocks.readFileSync }));
vi.mock('../../config', () => ({ config: { keysDir: '/keys', url: 'https://provider.example/' } }));
vi.mock('../logger', () => ({ logger: { child: () => ({ info: vi.fn() }) } }));
vi.mock('../util/util', () => ({ importPrivateKeyPem: mocks.importKey, getKeyAttestationCertificateChain: mocks.chain }));
vi.mock('jose', () => ({
	SignJWT: class {
		setIssuedAt() {
			return this;
		}
		setExpirationTime() {
			return this;
		}
		setProtectedHeader() {
			return this;
		}
		sign = mocks.sign;
	},
}));

beforeEach(() => {
	vi.resetModules();
	vi.clearAllMocks();
	mocks.readFileSync.mockImplementation((file: string) => `initial:${file}`);
	mocks.importKey.mockResolvedValue('key');
	mocks.chain.mockReturnValue([]);
	mocks.sign.mockResolvedValue('signed');
});

describe('wallet provider signing material', () => {
	it('issues status references under the public API', async () => {
		const { buildWalletProviderStatusClaim } = await import('./WalletProviderService');
		const reference = { id: 'entry', idx: 3, listId: 'list', maintenanceExpiresAt: 2000000000 };
		expect(buildWalletProviderStatusClaim(reference)).toEqual({
			status: { status_list: { idx: 3, uri: 'https://provider.example/wallet-provider/api/status-lists/list' } },
			exp: 2000000000,
		});
	});
	it('loads files on startup and reuses them for signing', async () => {
		const { signWalletProviderAttestation } = await import('./WalletProviderService');
		mocks.readFileSync.mockImplementation((file: string) => `rotated:${file}`);
		await signWalletProviderAttestation({}, 'key-attestation+jwt');
		await signWalletProviderAttestation({}, 'oauth-client-attestation+jwt');
		expect(mocks.importKey).toHaveBeenCalledWith('initial:/keys/wallet-provider.key', 'ES256');
		expect(mocks.chain).toHaveBeenCalledWith('initial:/keys/wallet-provider.pem');
		expect(mocks.readFileSync).toHaveBeenCalledTimes(3);
	});

	it.each(['wallet-provider.key', 'wallet-provider.pem', 'ca.pem'])('fails startup when %s is unavailable', async (name) => {
		const failure = new Error(`missing ${name}`);
		mocks.readFileSync.mockImplementation((file: string) => {
			if (file.endsWith(`/${name}`)) throw failure;
			return file;
		});
		await expect(import('./WalletProviderService')).rejects.toBe(failure);
	});
});

import { generateKeyPairSync } from 'node:crypto';
import { jwtVerify } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ importKey: vi.fn() }));
vi.mock('fs/promises', () => ({ readFile: vi.fn().mockResolvedValue('fixture') }));
vi.mock('../../config', () => ({ config: { keysDir: '/keys' } }));
vi.mock('../logger', () => ({ logger: { child: () => ({ info: vi.fn(), error: vi.fn() }) } }));
vi.mock('../util/util', () => ({
	importPrivateKeyPem: mocks.importKey,
	getKeyAttestationCertificateChain: () => ['certificate'],
}));
import { signWalletProviderAttestation } from './WalletProviderService';

const material = { privateKey: 'private-key', certificate: 'certificate' };
const types = ['key-attestation+jwt', 'oauth-client-attestation+jwt'] as const;

beforeEach(() => vi.clearAllMocks());

describe('wallet provider signing key validation', () => {
	it.each(types)('rejects an unsuccessful private key import for %s', async (type) => {
		mocks.importKey.mockResolvedValue(undefined);
		await expect(signWalletProviderAttestation({}, type, material)).rejects.toThrow('Failed to import wallet provider private key');
		expect(mocks.importKey).toHaveBeenCalledExactlyOnceWith('private-key', 'ES256');
	});

	it.each(types)('signs %s with an imported private key', async (type) => {
		const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
		mocks.importKey.mockResolvedValue(pair.privateKey);
		const token = await signWalletProviderAttestation({ nonce: 'nonce' }, type, material);
		const { payload, protectedHeader } = await jwtVerify(token, pair.publicKey);
		expect(payload).toMatchObject({ nonce: 'nonce', iat: expect.any(Number), exp: expect.any(Number) });
		expect(protectedHeader).toEqual({ alg: 'ES256', typ: type, x5c: ['certificate'] });
	});
});

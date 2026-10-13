import { Router } from 'express';
import { SignJWT } from 'jose';
import { deflateSync } from 'node:zlib';
import { signWalletProviderStatus } from './wallet_provider.router';
import { config } from '../../config';

const STATUS_LIST_PATH = '/wallet-provider/status-lists/zero';
const VALID_LIST = deflateSync(Buffer.from([0])).toString('base64url');

const statusListUri = `${config.url.replace(/\/+$/, '')}${STATUS_LIST_PATH}`;

const walletProviderStatusListRouter = Router();


walletProviderStatusListRouter.get('/zero', async (_req, res) => {
	res.set('Cache-Control', 'no-store');
	try {
		const token = await signWalletProviderStatus(new SignJWT({
			ttl: 60,
			status_list: { bits: 1, lst: VALID_LIST },
		})
			.setSubject(statusListUri)
			.setIssuedAt()
			.setExpirationTime('60s'));
		return res.type('application/statuslist+jwt').send(token);
	} catch (err) {
		console.error('Mock status list signing failed', err);
		return res.status(503).send({ error: 'STATUS_LIST_UNAVAILABLE' });
	}
});

export {
	walletProviderStatusListRouter,
}

/** Every WIA and KA shares the first entry; this mock cannot revoke attestations. */
export function zeroStatusListReference() {
	return {
		status: { status_list: { idx: 0, uri: statusListUri } },
		exp: Math.floor(Date.now() / 1000) + 32 * 24 * 60 * 60,
	};
}

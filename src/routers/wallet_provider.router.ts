import { Router } from "express";
import { SignJWT } from "jose";
import type { JWK } from "jose";
import { config } from "../../config";
import type { WalletProviderSigningMaterial } from "../services/WalletProviderService";
import { allocateWalletProviderStatus, revokeWalletProviderStatus, getWalletProviderStatusList, WalletProviderStatusErr, STATUS_TOKEN_SECONDS } from "../entities/WalletProviderStatus.entity";
import { AuthMiddleware } from "../middlewares/auth.middleware";
import { loadWalletProviderSigningMaterial, signWalletProviderAttestation, buildWalletProviderStatusClaim, signWalletProviderStatus } from "../services/WalletProviderService";

type KeyAttestationRequestBody = {
	jwks: JWK[];
	openid4vci: {
		nonce: string;
	};
};

type WalletInstanceAttestationRequestBody = {
	/** Expected to contain exactly one public wallet-instance key. */
	jwks: JWK[];
	openid4vci: {
		client_id: string;
		authorization_server: string;
	};
};

const walletProviderUrl = config.url.replace(/\/+$/, '');
const walletProviderRouter = Router();

walletProviderRouter.post('/key-attestation/generate', AuthMiddleware, async (req, res) => {

	const { jwks, openid4vci }: Partial<KeyAttestationRequestBody> = req.body ?? {};
	const nonce = openid4vci?.nonce;

	if (!jwks || !Array.isArray(jwks) || jwks.length == 0) {
		const errorResponse = {
			error: "INVALID_JWKS",
			message: "'jwks' JSON body parameter is missing or not type of 'array' or array is empty",
		};
		console.log(errorResponse);
		return res.status(400).send(errorResponse);
	}

	if (!nonce || typeof nonce !== 'string') {
		const errorResponse = {
			error: "INVALID_OPENID4VCI_NONCE_VALUE",
			message: "'openid4vci.nonce' JSON body parameter is missing or not type of 'string'",
		};
		console.log(errorResponse);
		return res.status(400).send(errorResponse);
	}

	let signingMaterial: WalletProviderSigningMaterial;

	try {
		signingMaterial = await loadWalletProviderSigningMaterial(true);
	}
	catch (err) {
		const errorResponse = {
			error: "UNSUPPORTED",
			message: "key attestation generation is not supported",
		};
		console.error(err);
		console.log(errorResponse);
		return res.status(400).send(errorResponse);
	}

	try {
		const allocation = await allocateWalletProviderStatus(req.user.id.id, 'ka');
		if (allocation.ok === false) {
			if (allocation.val === WalletProviderStatusErr.WALLET_REVOKED) {
				return res.status(403).send({ error: 'WALLET_REVOKED' });
			}
			return res.status(503).send({ error: 'STATUS_UNAVAILABLE' });
		}
		const entry = allocation.val;
		const keyAttestation = await signWalletProviderAttestation({
			attested_keys: jwks,
			nonce: nonce,
			key_storage: ['iso_18045_basic'],
			user_authentication: ['iso_18045_basic'],
			certification: `${walletProviderUrl}/certification`,
			key_storage_status: buildWalletProviderStatusClaim(entry),
		}, 'key-attestation+jwt', signingMaterial);

		return res.send({ key_attestation: keyAttestation });
	}
	catch (err) {
		console.error(err);
		return res.status(503).send({
			error: "FAILED",
			message: "key attestation signature generation failed",
		});
	}
});

walletProviderRouter.post('/wallet-instance-attestation/generate', AuthMiddleware, async (req, res) => {
	const { jwks, openid4vci }: WalletInstanceAttestationRequestBody = req.body ?? {};

	if (!jwks || !Array.isArray(jwks) || jwks.length === 0) {
		return res.status(400).send({
			error: "INVALID_JWKS",
			message: "'jwks' JSON body parameter is missing or not type of 'array' or array is empty",
		});
	}

	const walletInstanceKey = jwks[0];
	if (!walletInstanceKey || typeof walletInstanceKey !== 'object' || Array.isArray(walletInstanceKey)) {
		return res.status(400).send({
			error: "INVALID_JWK",
			message: "'jwks[0]' must be the Wallet Unit proof-of-possession public JWK",
		});
	}

	const clientId = openid4vci?.client_id;
	if (typeof clientId !== 'string' || clientId.trim().length === 0) {
		return res.status(400).send({
			error: "INVALID_OPENID4VCI_CLIENT_ID",
			message: "'openid4vci.client_id' must be a non-empty string",
		});
	}

	const authorizationServer = openid4vci?.authorization_server;
	if (typeof authorizationServer !== 'string' || authorizationServer.trim().length === 0) {
		return res.status(400).send({
			error: "INVALID_OPENID4VCI_AUTHORIZATION_SERVER",
			message: "'openid4vci.authorization_server' must be a non-empty string",
		});
	}

	let signingMaterial: WalletProviderSigningMaterial;

	try {
		signingMaterial = await loadWalletProviderSigningMaterial();
	}
	catch (err) {
		console.error(err);
		return res.status(400).send({
			error: "UNSUPPORTED",
			message: "Wallet Instance Attestation generation is not supported",
		});
	}

	try {
		const allocation = await allocateWalletProviderStatus(req.user.id.id, 'wia');
		if (allocation.ok === false) {
			if (allocation.val === WalletProviderStatusErr.WALLET_REVOKED) {
				return res.status(403).send({ error: 'WALLET_REVOKED' });
			}
			return res.status(503).send({ error: 'STATUS_UNAVAILABLE' });
		}
		const entry = allocation.val;

		const walletInstanceAttestation = await signWalletProviderAttestation({
			jti: entry.id,
			sub: clientId,
			aud: authorizationServer,
			cnf: { jwk: walletInstanceKey },
			wallet_name: 'WE BUILD wwWallet',
			wallet_link: 'https://webuild.wwwallet.org',
			wallet_version: '1.0.0',
			wallet_solution_certification_information: 'Development instance — no wallet solution certification asserted',
			client_status: buildWalletProviderStatusClaim(entry),
		}, 'oauth-client-attestation+jwt', signingMaterial);

		return res.send({ wallet_instance_attestation: walletInstanceAttestation });
	}
	catch (err) {
		console.error(err);
		return res.status(503).send({
			error: "FAILED",
			message: "Wallet Instance Attestation signature generation failed",
		});
	}
});

walletProviderRouter.get('/status-lists/:statusListId', async (req, res) => {
	if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(req.params.statusListId)) {
		return res.status(404).json({ error: 'NOT_FOUND' });
	}
	if (req.query.time !== undefined) {
		return res.status(501).json({ error: 'HISTORICAL_STATUS_NOT_IMPLEMENTED' });
	}
	if (!req.accepts('application/statuslist+jwt')) {
		return res.status(406).json({ error: 'UNSUPPORTED_STATUS_LIST_FORMAT' });
	}
	try {
		const list = await getWalletProviderStatusList(req.params.statusListId);
		if (list.ok === false) {
			if (list.val === WalletProviderStatusErr.NOT_EXISTS) {
				return res.status(404).json({ error: 'NOT_FOUND' });
			}
			return res.status(503).json({ error: 'STATUS_LIST_UNAVAILABLE' });
		}
		const token = await signWalletProviderStatus(new SignJWT({
			sub: `${walletProviderUrl}/wallet-provider/status-lists/${req.params.statusListId}`,
			ttl: STATUS_TOKEN_SECONDS,
			status_list: list.val,
		})
			.setIssuedAt()
			.setExpirationTime(`${STATUS_TOKEN_SECONDS}s`));
		return res
			.status(200)
			.set('Cache-Control', 'no-store')
			.type('application/statuslist+jwt')
			.send(token);
	} catch {
		return res.status(503).json({ error: 'STATUS_LIST_UNAVAILABLE' });
	}
});

walletProviderRouter.post('/status-lists/revoke', AuthMiddleware, async (req, res) => {
	if (!req.user) {
		return res.status(401).send();
	}
	try {
		const revoked = await revokeWalletProviderStatus(req.user.id.id);
		if (revoked.err) {
			return res.status(503).json({ error: 'STATUS_UNAVAILABLE' });
		}
		return res.status(204).send();
	} catch {
		return res.status(503).json({ error: 'STATUS_UNAVAILABLE' });
	}
});

walletProviderRouter.get('/certification', (_req, res) => {
	if (process.env.NODE_ENV === 'production') {
		return res.status(404).send();
	}
	return res.type('html')
		.send('<!doctype html><html lang="en"><meta charset="utf-8">'
			+ '<title>Mock wallet certification</title><h1>Development mock</h1>'
			+ '<p>No WSCD or keystore certification is asserted. This page is an integration fixture.</p></html>'
		);
});

export {
	walletProviderRouter,
}

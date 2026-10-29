import { Router } from "express";
import { SignJWT } from "jose";
import { config } from "../../config";
import type { WalletProviderSigningMaterial } from "../services/WalletProviderService";
import { allocateWalletProviderStatus, revokeWalletProviderStatus, getWalletProviderStatusList, WalletProviderStatusErr, STATUS_TOKEN_SECONDS } from "../entities/WalletProviderStatus.entity";
import { AuthMiddleware } from "../middlewares/auth.middleware";
import { buildWalletProviderStatusClaim, loadWalletProviderSigningMaterial, signWalletProviderAttestation, signWalletProviderStatus } from "../services/WalletProviderService";
import { logger } from "../logger";
import { loadWalletProviderAttestationProfile } from "../services/walletProviderAttestation";
import { AttestationRequestValidationError, parseKeyAttestationRequest } from "../services/KeyAttestationService";
import { parseWalletAttestationRequest } from "../services/WalletAttestationService";

const log = logger.child({ module: "WalletProviderRouter" });

const walletProviderUrl = `${config.url.replace(/\/+$/, '')}/wallet-provider`;
const walletProviderRouter = Router();
const attestationProfile = loadWalletProviderAttestationProfile(config.walletProviderAttestationProfile);

walletProviderRouter.post('/key-attestation/generate', AuthMiddleware, async (req, res) => {
	if (!req.user) {
		return res.status(401).send();
	}

	let input: ReturnType<typeof parseKeyAttestationRequest>;
	try {
		input = parseKeyAttestationRequest(req.body);
	} catch (err) {
		if (!(err instanceof AttestationRequestValidationError)) throw err;
		return res.status(400).send(err.response);
	}

	let signingMaterial: WalletProviderSigningMaterial;

	try {
		signingMaterial = await loadWalletProviderSigningMaterial(true);
	}
	catch (err) {
		const errorResponse = {
			error: 'UNSUPPORTED',
			message: 'key attestation generation is not supported',
		};
		log.error({ err, errorResponse }, 'Key attestation generation is not supported');
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
		const keyAttestation = await signWalletProviderAttestation(
			attestationProfile.buildKeyAttestationPayload({
				...input, issuer: walletProviderUrl,
				keyStorageStatus: buildWalletProviderStatusClaim(allocation.val),
			}),
			'key-attestation+jwt', signingMaterial);

		return res.send({ key_attestation: keyAttestation });
	}
	catch (err) {
		log.error({ err }, "Failed to sign key attestation");
		return res.status(503).send({
			error: "FAILED",
			message: "key attestation signature generation failed",
		});
	}
});

walletProviderRouter.post('/wallet-attestation/generate', AuthMiddleware, async (req, res) => {
	if (!req.user) {
		return res.status(401).send();
	}

	let input: ReturnType<typeof parseWalletAttestationRequest>;
	try {
		input = parseWalletAttestationRequest(req.body);
	} catch (err) {
		if (!(err instanceof AttestationRequestValidationError)) throw err;
		return res.status(400).send(err.response);
	}

	let signingMaterial: WalletProviderSigningMaterial;

	try {
		signingMaterial = await loadWalletProviderSigningMaterial();
	}
	catch (err) {
		log.error({ err }, "Wallet instance attestation generation is not supported");
		return res.status(400).send({
			error: "UNSUPPORTED",
			message: "Wallet Instance Attestation generation is not supported",
		});
	}

	try {
		const allocation = await allocateWalletProviderStatus(req.user.id.id, 'wa');
		if (allocation.ok === false) {
			if (allocation.val === WalletProviderStatusErr.WALLET_REVOKED) {
				return res.status(403).send({ error: 'WALLET_REVOKED' });
			}
			return res.status(503).send({ error: 'STATUS_UNAVAILABLE' });
		}
		const walletInstanceAttestation = await signWalletProviderAttestation(
			attestationProfile.buildWalletAttestationPayload({
				key: input.key, clientId: input.clientId, issuer: walletProviderUrl,
				authorizationServer: input.authorizationServer, attestationId: allocation.val.id,
				clientStatus: buildWalletProviderStatusClaim(allocation.val),
			}),
			'oauth-client-attestation+jwt', signingMaterial);

		return res.send({ wallet_instance_attestation: walletInstanceAttestation });
	}
	catch (err) {
		log.error({ err }, "Wallet instance attestation signature generation failed");
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
			sub: `${walletProviderUrl}/status-lists/${req.params.statusListId}`,
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
	const page = attestationProfile.getCertificationPage();
	if (page === undefined) {
		return res.status(404).send();
	}
	return res.type('html').send(page);
});

export {
	walletProviderRouter,
}

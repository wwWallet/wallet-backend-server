import path from "node:path";
import { Router } from "express";
import { z, ZodError } from "zod";
import { config } from "../../config";
import {
	DevelopmentWalletProviderEvidenceVerifier,
	EvidenceRejectedError,
	EvidenceVerifierUnavailableError,
	RemoteWalletProviderEvidenceVerifier,
	UnconfiguredWalletProviderEvidenceVerifier,
	WalletProviderEvidenceVerifier,
} from "../wallet-provider/evidenceVerifier";
import {
	InvalidPublicJwkError,
	loadWalletProviderSigner,
	normalizeAndThumbprintPublicJwks,
} from "../wallet-provider/keyAttestation";
import { signStatusListToken } from "../wallet-provider/statusList";
import {
	AttestedKeyAlreadyUsedError,
	KeyAttestationAlreadyConsumedError,
	WalletInstanceNotFoundError,
	WalletInstanceRevokedError,
	WalletProviderService,
} from "../wallet-provider/walletProviderService";

const evidenceSchema = z.record(z.unknown()).refine(
	value => Buffer.byteLength(JSON.stringify(value), "utf8") <= 128 * 1024,
	"Evidence must not exceed 128 KiB",
);

const activationRequestSchema = z.object({
	wallet_name: z.string().trim().min(1).max(255),
	wallet_version: z.string().trim().min(1).max(64),
	activation_evidence: evidenceSchema,
}).strict();

const keyAttestationRequestSchema = z.object({
	wallet_instance_id: z.string().uuid(),
	jwks: z.array(z.unknown()).min(1).max(32),
	key_attestation_evidence: evidenceSchema,
	proof_type: z.enum(["jwt", "attestation"]).default("jwt"),
	preferred_key_storage_status_period: z.number().int().positive().optional(),
	openid4vci: z.object({
		nonce: z.string().min(1).max(2048).optional(),
	}).strict().optional(),
}).strict().superRefine((request, context) => {
	const nonce = request.openid4vci?.nonce;
	if (request.proof_type === "attestation" && nonce === undefined) {
		context.addIssue({
			code: z.ZodIssueCode.custom,
			path: ["openid4vci", "nonce"],
			message: "A c_nonce is required for an attestation proof",
		});
	}
	if (request.proof_type === "jwt" && nonce !== undefined) {
		context.addIssue({
			code: z.ZodIssueCode.custom,
			path: ["openid4vci", "nonce"],
			message: "The nonce belongs in the JWT proof payload, not in the Key Attestation",
		});
	}
});

const revocationRequestSchema = z.object({
	reason: z.string().trim().min(1).max(512),
}).strict();

const walletProviderRouter = Router();
const walletProviderPublicRouter = Router();

const keysDir: string = config.keysDir ?? "/app/keys";
const privateKeyPath = config.walletProvider.privateKeyPath ?? path.join(keysDir, "wallet-provider.key");
const certificateChainPaths = config.walletProvider.certificateChainPaths ?? [path.join(keysDir, "wallet-provider.pem")];
const walletProviderBaseUrl = new URL(config.url);
if (process.env.NODE_ENV === "production" && walletProviderBaseUrl.protocol !== "https:") {
	throw new Error("The production Wallet Provider public URL must use HTTPS");
}
let signerPromise: ReturnType<typeof loadWalletProviderSigner> | undefined;
const getSigner = () => signerPromise ??= loadWalletProviderSigner(privateKeyPath, certificateChainPaths);

const evidenceVerifier = createEvidenceVerifier();
const walletProviderService = new WalletProviderService(evidenceVerifier, getSigner, {
	baseUrl: walletProviderBaseUrl.toString(),
	keyAttestationTtlSeconds: config.walletProvider.keyAttestationTtlSeconds,
	statusMaintenanceSeconds: config.walletProvider.statusMaintenanceSeconds,
	maxStatusMaintenanceSeconds: config.walletProvider.maxStatusMaintenanceSeconds,
	statusListCapacity: config.walletProvider.statusListCapacity,
});

walletProviderRouter.post("/instances/activate", async (req, res) => {
	try {
		const request = activationRequestSchema.parse(req.body);
		const instance = await walletProviderService.activateWalletInstance({
			userId: req.user.id.id,
			walletName: request.wallet_name,
			walletVersion: request.wallet_version,
			activationEvidence: request.activation_evidence,
		});
		return res.status(201).send({
			wallet_instance_id: instance.id,
			state: instance.state,
			created_at: instance.createdAt,
		});
	}
	catch (error) {
		return sendWalletProviderError(res, error);
	}
});

const issueKeyAttestation = async (req, res) => {
	try {
		const request = keyAttestationRequestSchema.parse(req.body);
		const { jwks, thumbprints } = await normalizeAndThumbprintPublicJwks(request.jwks);
		const result = await walletProviderService.issueKeyAttestation({
			userId: req.user.id.id,
			walletInstanceId: request.wallet_instance_id,
			jwks,
			thumbprints,
			keyEvidence: request.key_attestation_evidence,
			preferredStatusPeriod: request.preferred_key_storage_status_period,
			nonce: request.proof_type === "attestation" ? request.openid4vci.nonce : undefined,
		});
		return res.status(201).send({
			id: result.id,
			key_attestation: result.keyAttestation,
			expires_at: result.tokenExpiresAt,
			key_storage_status_expires_at: result.maintenanceExpiresAt,
		});
	}
	catch (error) {
		return sendWalletProviderError(res, error);
	}
};

walletProviderRouter.post("/key-attestations", issueKeyAttestation);

// Transitional alias for callers of the old stateless endpoint. It now uses
// the same authenticated, instance-bound and evidence-verified implementation.
walletProviderRouter.post("/key-attestation/generate", (req, res, next) => {
	res.setHeader("Deprecation", "true");
	res.setHeader("Link", "</wallet-provider/key-attestations>; rel=successor-version");
	return issueKeyAttestation(req, res).catch(next);
});

walletProviderRouter.post("/key-attestations/:id/consume", async (req, res) => {
	try {
		const id = z.string().uuid().parse(req.params.id);
		await walletProviderService.consumeKeyAttestation(req.user.id.id, id);
		return res.status(204).send();
	}
	catch (error) {
		return sendWalletProviderError(res, error);
	}
});

walletProviderRouter.post("/instances/:id/revoke", async (req, res) => {
	try {
		const id = z.string().uuid().parse(req.params.id);
		const request = revocationRequestSchema.parse(req.body);
		await walletProviderService.revokeWalletInstance(req.user.id.id, id, request.reason);
		return res.status(204).send();
	}
	catch (error) {
		return sendWalletProviderError(res, error);
	}
});

walletProviderPublicRouter.get("/status/ka/:listId", async (req, res) => {
	try {
		const listId = z.coerce.number().int().positive().parse(req.params.listId);
		const statusList = await walletProviderService.getStatusList(listId);
		const issuedAt = Math.floor(Date.now() / 1000);
		const ttl = config.walletProvider.statusListTtlSeconds;
		const uri = walletProviderService.statusListUri(listId);
		const token = await signStatusListToken({
			uri,
			capacity: statusList.capacity,
			invalidIndexes: statusList.invalidIndexes,
			issuedAt,
			expiresAt: issuedAt + ttl,
			ttl,
			signer: await getSigner(),
		});
		res.setHeader("Content-Type", "application/statuslist+jwt");
		res.setHeader("Cache-Control", `public, max-age=${ttl}, no-transform`);
		return res.send(token);
	}
	catch (error) {
		return sendWalletProviderError(res, error);
	}
});

function createEvidenceVerifier(): WalletProviderEvidenceVerifier {
	if (config.walletProvider.evidenceVerifierUrl) {
		const verifierUrl = new URL(config.walletProvider.evidenceVerifierUrl);
		if (process.env.NODE_ENV === "production" && verifierUrl.protocol !== "https:") {
			throw new Error("The production evidence verifier URL must use HTTPS");
		}
		return new RemoteWalletProviderEvidenceVerifier(
			verifierUrl.toString(),
			config.walletProvider.evidenceVerifierBearerToken,
			config.walletProvider.evidenceVerifierTimeoutMilliseconds,
		);
	}
	if (config.walletProvider.devAcceptUnverifiedEvidence) {
		if (
			config.walletProvider.devKeyStorage.length === 0 ||
			config.walletProvider.devUserAuthentication.length === 0 ||
			!config.walletProvider.devCertification
		) {
			throw new Error("Development key-attestation assurance claims are incomplete");
		}
		return new DevelopmentWalletProviderEvidenceVerifier({
			keyStorage: config.walletProvider.devKeyStorage,
			userAuthentication: config.walletProvider.devUserAuthentication,
			certification: config.walletProvider.devCertification,
		});
	}
	return new UnconfiguredWalletProviderEvidenceVerifier();
}

function sendWalletProviderError(res, error: unknown) {
	if (error instanceof ZodError || error instanceof RangeError || error instanceof InvalidPublicJwkError) {
		return res.status(400).send({
			error: "INVALID_REQUEST",
			message: error.message,
		});
	}
	if (error instanceof EvidenceRejectedError) {
		return res.status(422).send({
			error: "INVALID_INTEGRITY_EVIDENCE",
			message: error.message,
		});
	}
	if (error instanceof EvidenceVerifierUnavailableError) {
		return res.status(503).send({
			error: "EVIDENCE_VERIFIER_UNAVAILABLE",
			message: error.message,
		});
	}
	if (error instanceof WalletInstanceNotFoundError) {
		return res.status(404).send({ error: "NOT_FOUND", message: error.message });
	}
	if (error instanceof WalletInstanceRevokedError) {
		return res.status(403).send({ error: "WALLET_INSTANCE_REVOKED", message: error.message });
	}
	if (error instanceof AttestedKeyAlreadyUsedError || error instanceof KeyAttestationAlreadyConsumedError) {
		return res.status(409).send({ error: "ATTESTATION_CONFLICT", message: error.message });
	}

	console.error("Wallet Provider operation failed", error);
	return res.status(500).send({
		error: "WALLET_PROVIDER_FAILURE",
		message: "Wallet Provider operation failed",
	});
}

export {
	walletProviderPublicRouter,
	walletProviderRouter,
};

import dotenv from 'dotenv';
dotenv.config();

function positiveInteger(value: string | undefined, fallback: number): number {
	const parsed = Number(value);
	return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export const config = {
	url: process.env.APP_URL || "${SERVICE_URL}",
	port: process.env.PORT || "${SERVICE_PORT}",
	appSecret: process.env.APP_SECRET || "${SERVICE_SECRET}",
	ssl: process.env.SSL_FLAG || "${SSL_FLAG}",
	db: {
		host: process.env.DB_HOST || "${DB_HOST}",
		port: process.env.DB_PORT || "${DB_PORT}",
		username: process.env.DB_USER || "${DB_USER}",
		password: process.env.DB_PASSWORD || "${DB_PASSWORD}",
		dbname: process.env.DB_NAME || "${DB_NAME}"
	},
	walletClientUrl: process.env.WALLET_CLIENT_URL || "${WALLET_CLIENT_URL}",
	webauthn: {
		attestation: "direct",
		origin: (process.env.WEBAUTHN_ORIGIN ? process.env.WEBAUTHN_ORIGIN.split(',') : undefined) || "${WEBAUTHN_ORIGIN}",
		rp: {
			id: process.env.WEBAUTHN_RP_ID || "${WEBAUTHN_RP_ID}",
			name: process.env.WEBAUTHN_RP_NAME || "wwWallet demo",
		},
	},
	alg: process.env.ALG || "EdDSA",
	keysDir: process.env.KEYS_DIR || undefined,
	walletProvider: {
		privateKeyPath: process.env.WALLET_PROVIDER_PRIVATE_KEY_PATH || undefined,
		certificateChainPaths: process.env.WALLET_PROVIDER_CERTIFICATE_CHAIN_PATHS
			?.split(',')
			.map(value => value.trim())
			.filter(Boolean),
		evidenceVerifierUrl: process.env.WALLET_PROVIDER_EVIDENCE_VERIFIER_URL || undefined,
		evidenceVerifierBearerToken: process.env.WALLET_PROVIDER_EVIDENCE_VERIFIER_BEARER_TOKEN || undefined,
		evidenceVerifierTimeoutMilliseconds: positiveInteger(process.env.WALLET_PROVIDER_EVIDENCE_VERIFIER_TIMEOUT_MS, 5000),
		keyAttestationTtlSeconds: positiveInteger(process.env.WALLET_PROVIDER_KEY_ATTESTATION_TTL_SECONDS, 900),
		statusMaintenanceSeconds: positiveInteger(process.env.WALLET_PROVIDER_STATUS_MAINTENANCE_SECONDS, 32 * 24 * 60 * 60),
		maxStatusMaintenanceSeconds: positiveInteger(process.env.WALLET_PROVIDER_MAX_STATUS_MAINTENANCE_SECONDS, 366 * 24 * 60 * 60),
		statusListCapacity: positiveInteger(process.env.WALLET_PROVIDER_STATUS_LIST_CAPACITY, 10000),
		statusListTtlSeconds: positiveInteger(process.env.WALLET_PROVIDER_STATUS_LIST_TTL_SECONDS, 300),
		devAcceptUnverifiedEvidence: process.env.DEV_WALLET_PROVIDER_ACCEPT_UNVERIFIED_EVIDENCE?.toLowerCase() === "true",
		devKeyStorage: process.env.DEV_WALLET_PROVIDER_KEY_STORAGE?.split(',').map(value => value.trim()).filter(Boolean) ?? [],
		devUserAuthentication: process.env.DEV_WALLET_PROVIDER_USER_AUTHENTICATION?.split(',').map(value => value.trim()).filter(Boolean) ?? [],
		devCertification: process.env.DEV_WALLET_PROVIDER_CERTIFICATION || undefined,
	},
	ohttpGatewayUrl: process.env.OHTTP_GATEWAY_URL || "http://localhost:4567",
	registerDisabled: process.env.REGISTRATION_DISABLED?.toLowerCase() === "true",
	debugAcceptUnauthorizedHttps: (process.env.DEBUG_ACCEPT_UNAUTHORIZED_HTTPS &&
		process.env.DEBUG_ACCEPT_UNAUTHORIZED_HTTPS.toLowerCase() === "true") ?? false
}

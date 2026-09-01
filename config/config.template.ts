import dotenv from 'dotenv';
dotenv.config();

function getPositiveInteger(value: string | undefined, fallback: number): number {
	const parsed = Number.parseInt(value || '', 10);
	return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
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
	ohttpGatewayUrl: process.env.OHTTP_GATEWAY_URL || "http://localhost:4567",
	metadata: {
		fidoUrl: process.env.METADATA_FIDO_URL || "https://c-mds.fidoalliance.org",
			communityAaguidUrl: process.env.METADATA_COMMUNITY_AAGUID_URL || "https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/aaguid.json",
		refreshIntervalMs: getPositiveInteger(process.env.METADATA_REFRESH_INTERVAL_MS, 7 * 24 * 60 * 60 * 1000),
	},
	registerDisabled: process.env.REGISTRATION_DISABLED?.toLowerCase() === "true",
	debugAcceptUnauthorizedHttps: (process.env.DEBUG_ACCEPT_UNAUTHORIZED_HTTPS &&
		process.env.DEBUG_ACCEPT_UNAUTHORIZED_HTTPS.toLowerCase() === "true") ?? false
}

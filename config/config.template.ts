import dotenv from 'dotenv';
dotenv.config();

export const config = {
	url: process.env.APP_URL || "SERVICE_URL",
	port: process.env.PORT || "SERVICE_PORT",
	appSecret: process.env.APP_SECRET || "SERVICE_SECRET",
	ssl: process.env.SSL_FLAG || "SSL_FLAG",
	db: {
		host: process.env.DB_HOST || "DB_HOST",
		port: process.env.DB_PORT || "DB_PORT",
		username: process.env.DB_USER || "DB_USER",
		password: process.env.DB_PASSWORD || "DB_PASSWORD",
		dbname: process.env.DB_NAME || "DB_NAME"
	},
	walletClientUrl: process.env.WALLET_CLIENT_URL || "WALLET_CLIENT_URL",
	webauthn: {
		attestation: "direct",
		origin: process.env.WEBAUTHN_ORIGIN.split(',') || "WEBAUTHN_ORIGIN",
		rp: {
			id: process.env.WEBAUTHN_RP_ID || "WEBAUTHN_RP_ID",
			name: process.env.WEBAUTHN_RP_NAME || "wwWallet demo",
		},
	},
	alg: process.env.ALG || "EdDSA",
	notifications: {
		enabled: process.env.NOTIFICATIONS_ENABLED === 'true' || true,
		serviceAccount: process.env.FIREBASE_CONFIG || "firebaseConfig.json"
	},
	keysDir: process.env.KEYS_DIR || undefined
}

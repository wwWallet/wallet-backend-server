export const config = {
	url: "SERVICE_URL",
	port: "SERVICE_PORT",
	appSecret: "SERVICE_SECRET",
	ssl: "SSL_FLAG",
	db: {
		host: "DB_HOST",
		port: "DB_PORT",
		username: "DB_USER",
		password: "DB_PASSWORD",
		dbname: "DB_NAME"
	},
	walletClientUrl: "WALLET_CLIENT_URL",
	webauthn: {
		attestation: "direct",
		origin: "WEBAUTHN_ORIGIN",
		rp: {
			id: "WEBAUTHN_RP_ID",
			name: "wwWallet demo",
		},
	},
	alg: "EdDSA",
	notifications: {
		enabled: "NOTIFICATIONS_ENABLED",
		serviceAccount: "firebaseConfig.json"
	}
}

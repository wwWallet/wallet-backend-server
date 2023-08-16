export = {
	url: "SERVICE_URL",
	port: "SERVICE_PORT",
	appSecret: "SERVICE_SECRET",
	db: {
		host: "DB_HOST",
		port: "DB_PORT",
		username: "DB_USER",
		password: "DB_PASSWORD",
		dbname: "DB_NAME"
	},
	redis: {
		url: "REDIS_URL",
		password: undefined
	},
	walletClientUrl: "WALLET_CLIENT_URL",
	webauthn: {
		attestation: "direct",
		origin: "WEBAUTHN_ORIGIN",
		rp: {
			id: "WEBAUTHN_RP_ID",
			name: "Digital Wallet demo",
		},
	},
	alg: "ES256",
}

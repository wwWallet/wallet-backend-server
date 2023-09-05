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
	alg: "ES256",
	servicesConfiguration: {
		issuanceService: "OpenidForCredentialIssuanceService", // OpenidForCredentialIssuanceService or OpenidForCredentialIssuanceMattrV2Service
		didKeyService: "W3C", // W3C or EBSI
	}
}
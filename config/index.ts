export const config = {
	url: "http://wallet-backend-server:8002",
	port: "8002",
	appSecret: "dsfkwfkwfwdfdsfSaSe2e34r4frwr42rAFdsf2",
	ssl: "SSL_FLAG",
	db: {
		host: "wallet-db",
		port: "3307",
		username: "root",
		password: "root",
		dbname: "wallet"
	},
	walletClientUrl: "http://localhost:3000/cb",
	webauthn: {
		attestation: "direct",
		origin: "http://localhost:3000",
		rp: {
			id: "localhost",
			name: "wwWallet demo",
		},
	},
	alg: "EdDSA",
	notifications: {
		enabled: true,
		serviceAccount: "firebaseConfig.json"
	}
}
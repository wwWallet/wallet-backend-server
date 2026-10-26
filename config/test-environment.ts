// Synthetic configuration shared by tests; spread it before applying per-test overrides.
export const testEnv = Object.freeze({
	NODE_ENV: 'test',
	DOTENV_CONFIG_QUIET: 'true',
	PORT: '8002',
	APP_SECRET: 'synthetic-unit-test-secret',
	DB_HOST: 'database.invalid',
	DB_PORT: '3306',
	DB_USER: 'unit-test',
	DB_PASSWORD: 'synthetic-password',
	DB_NAME: 'unit-test',
	WEBAUTHN_ORIGIN: 'https://wallet.example',
	WEBAUTHN_RP_ID: 'wallet.example',
});

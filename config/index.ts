import dotenv from 'dotenv';
import { z } from 'zod';
dotenv.config();

// Empty values count as unset
const env = (name: string): string | undefined => process.env[name] || undefined;

const required = z.string({ required_error: "is required" });
const port = required.regex(/^\d+$/, "must be a port number")
	.transform(Number)
	.refine((n) => n > 0 && n < 65536, "must be a port number");
const flag = z.string().optional().transform((value) => value?.toLowerCase() === "true");

// APP_SECRET value in .env.template: fine for local development, refused in production
const DEV_APP_SECRET = "dev-only-insecure-secret";

function positiveInteger(value: string | undefined, fallback: number): number {
	const parsed = Number.parseInt(value || '', 10);
	return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

const schema = z.object({
	PORT: port,
	APP_URL: z.string().optional(),
	APP_SECRET: required
		.refine((value) => value !== "${SERVICE_SECRET}", "must not be the template placeholder")
		.refine((value) => process.env.NODE_ENV !== "production" || value !== DEV_APP_SECRET, "must not be the .env.template value in production"),
	DB_HOST: required,
	DB_PORT: port,
	DB_USER: required,
	DB_PASSWORD: required,
	DB_NAME: required,
	WEBAUTHN_ORIGIN: required.transform((value) => value.split(',').map((origin) => origin.trim()).filter(Boolean)),
	WEBAUTHN_RP_ID: required,
	WEBAUTHN_RP_NAME: z.string().default("wwWallet demo"),
	KEYS_DIR: z.string().default("/app/keys"),
	OHTTP_GATEWAY_URL: z.string().default("http://localhost:4567"),
	METADATA_FIDO_URL: z.string().default("https://c-mds.fidoalliance.org"),
	METADATA_COMMUNITY_AAGUID_URL: z.string().default("https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/aaguid.json"),
	METADATA_REFRESH_INTERVAL_MS: z.string().optional().transform((value) => positiveInteger(value, 604800000)),
	REGISTRATION_DISABLED: flag,
	DEBUG_ACCEPT_UNAUTHORIZED_HTTPS: flag,
});

const parsed = schema.safeParse(Object.fromEntries(Object.keys(schema.shape).map((name) => [name, env(name)])));
if (!parsed.success) {
	const problems = parsed.error.issues.map((issue) => `  - ${issue.path.join('.')} ${issue.message}`).join('\n');
	throw new Error(`Invalid wallet-backend-server configuration (see .env.template):\n${problems}`);
}
const vars = parsed.data;

export const config = {
	url: vars.APP_URL ?? `http://localhost:${vars.PORT}`,
	port: vars.PORT,
	appSecret: vars.APP_SECRET,
	db: {
		host: vars.DB_HOST,
		port: vars.DB_PORT,
		username: vars.DB_USER,
		password: vars.DB_PASSWORD,
		dbname: vars.DB_NAME,
	},
	webauthn: {
		attestation: "direct" as const,
		origin: vars.WEBAUTHN_ORIGIN,
		rp: {
			id: vars.WEBAUTHN_RP_ID,
			name: vars.WEBAUTHN_RP_NAME,
		},
	},
	keysDir: vars.KEYS_DIR,
	ohttpGatewayUrl: vars.OHTTP_GATEWAY_URL,
	metadata: {
		fidoUrl: vars.METADATA_FIDO_URL,
		communityAaguidUrl: vars.METADATA_COMMUNITY_AAGUID_URL,
		refreshIntervalMs: vars.METADATA_REFRESH_INTERVAL_MS,
	},
	registerDisabled: vars.REGISTRATION_DISABLED,
	debugAcceptUnauthorizedHttps: vars.DEBUG_ACCEPT_UNAUTHORIZED_HTTPS,
};

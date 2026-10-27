import type { JWK, JWTPayload } from 'jose';
import { z } from 'zod';
import type { KeyStorageStatus } from './WeBuildProfile';

/** OID4VCI Appendix D.2 attack potential resistance values. */
export const attackPotentialResistanceSchema = z.enum([
	'iso_18045_high',
	'iso_18045_moderate',
	'iso_18045_enhanced-basic',
	'iso_18045_basic',
]);
export type AttackPotentialResistance = z.infer<typeof attackPotentialResistanceSchema>;

/** OID4VCI Appendix D.1 payload claims; signer/builder-owned claims are optional here. */
export const oid4vciKeyAttestationClaimsSchema = z.object({
	iat: z.number().int().optional(),
	exp: z.number().int().optional(),
	attested_keys: z.array(z.custom<JWK>((value) =>
		typeof value === 'object' && value !== null && typeof value.kty === 'string'
	)).nonempty().optional(),
	key_storage: z.array(attackPotentialResistanceSchema).nonempty().optional(),
	user_authentication: z.array(attackPotentialResistanceSchema).nonempty().optional(),
	certification: z.string().url().optional(),
	nonce: z.string().optional(),
	status: z.record(z.unknown()).optional(),
});
export type Oid4vciKeyAttestationClaims = z.infer<typeof oid4vciKeyAttestationClaimsSchema>;

/** Provider options exclude claims owned by the shared builder and signer. */
export type KeyAttestationOptions = Omit<Oid4vciKeyAttestationClaims, 'iat' | 'exp' | 'attested_keys' | 'nonce'>;

export type WalletProviderAttestationProfileId = 'OID4VCI' | 'WEBUILD';

export interface KeyAttestationInput {
	issuer?: string;
	keys: JWK[];
	nonce?: string;
	/** Independently verified provider claims, never copied from the HTTP request. */
	claims?: KeyAttestationOptions & { key_storage_status?: KeyStorageStatus };
	keyStorageStatus?: KeyStorageStatus;
}

export interface WalletProviderAttestationProfile {
	readonly id: WalletProviderAttestationProfileId;
	buildKeyAttestationPayload(input: KeyAttestationInput): JWTPayload;
	buildWalletAttestationPayload(input: WalletAttestationInput): JWTPayload;
	getCertificationPage(): string | undefined;
}

/** Provider-controlled OID4VCI wallet metadata; subject, cnf and times are shared-owned. */
export const walletAttestationOptionsSchema = z.object({
	iss: z.string().optional(),
	aud: z.string().optional(),
	jti: z.string().optional(),
	wallet_name: z.string().optional(),
	wallet_link: z.string().url().optional(),
	status: z.record(z.unknown()).optional(),
});
export type WalletAttestationOptions = z.infer<typeof walletAttestationOptionsSchema>;

export interface WalletAttestationInput {
	key: JWK;
	clientId: string;
	issuer: string;
	authorizationServer?: string;
	attestationId?: string;
	claims?: WalletAttestationOptions & Record<string, unknown>;
	clientStatus?: KeyStorageStatus;
}

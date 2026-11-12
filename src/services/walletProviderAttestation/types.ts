import type { JWK, JWTPayload } from 'jose';
import type { KeyStorageStatus } from './WeBuildProfile';

/** OPENID4VCI Appendix D.2 attack potential resistance values. */
export type AttackPotentialResistance = 'iso_18045_high' | 'iso_18045_moderate' | 'iso_18045_enhanced-basic' | 'iso_18045_basic';

/** OPENID4VCI Appendix D.1 payload claims; signer/builder-owned claims are optional here. */
export interface Oid4vciKeyAttestationClaims {
	iat?: number;
	exp?: number;
	attested_keys?: [JWK, ...JWK[]];
	key_storage?: [AttackPotentialResistance, ...AttackPotentialResistance[]];
	user_authentication?: [AttackPotentialResistance, ...AttackPotentialResistance[]];
	certification?: string;
	nonce?: string;
	status?: Record<string, unknown>;
}

/** Provider options exclude claims owned by the shared builder and signer. */
export type KeyAttestationOptions = Omit<Oid4vciKeyAttestationClaims, 'iat' | 'exp' | 'attested_keys' | 'nonce'>;

export type WalletProviderAttestationProfileId = 'OPENID4VCI' | 'WEBUILD';

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

/** Provider-controlled OPENID4VCI wallet metadata; subject, cnf and times are shared-owned. */
export interface WalletAttestationOptions {
	iss?: string;
	aud?: string;
	jti?: string;
	wallet_name?: string;
	wallet_link?: string;
	status?: Record<string, unknown>;
}

export interface WalletAttestationInput {
	key: JWK;
	clientId: string;
	issuer: string;
	authorizationServer?: string;
	attestationId?: string;
	claims?: WalletAttestationOptions & Record<string, unknown>;
	clientStatus?: KeyStorageStatus;
}

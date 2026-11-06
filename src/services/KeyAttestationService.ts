import { createPublicKey } from 'node:crypto';
import type { JWK, JWTPayload } from 'jose';
import type { KeyAttestationOptions } from './walletProviderAttestation/types';
import { logger } from '../logger';

const log = logger.child({ module: 'KeyAttestationService' });

const privateMembers = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];
const curves: Record<string, { bytes: number; alg: string }> = {
	'P-256': { bytes: 32, alg: 'ES256' },
	'P-384': { bytes: 48, alg: 'ES384' },
	'P-521': { bytes: 66, alg: 'ES512' },
	secp256k1: { bytes: 32, alg: 'ES256K' },
};

function decode(value: unknown): Buffer {
	if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
		throw new Error('Invalid public JWK encoding');
	}
	const bytes = Buffer.from(value, 'base64url');
	if (bytes.toString('base64url') !== value) {
		throw new Error('Invalid public JWK encoding');
	}
	return bytes;
}

/** Validate public signing-key material, not possession, origin or storage assurance. */
export function validatePublicAttestationKey(value: unknown): JWK {
	if (!value || typeof value !== 'object' || Array.isArray(value)) {
		throw new Error('Expected a public JWK');
	}
	const jwk = value as JWK;
	if (privateMembers.some((member) => Object.prototype.hasOwnProperty.call(jwk, member))) {
		throw new Error('Private or symmetric key material is forbidden');
	}
	if (jwk.ext !== undefined && typeof jwk.ext !== 'boolean') {
		throw new Error('Invalid JWK ext');
	}
	if (jwk.use !== undefined && typeof jwk.use !== 'string') {
		throw new Error('Invalid JWK use');
	}
	if (jwk.use !== undefined && jwk.use !== 'sig') {
		log.warn('Expected signing use in JWK use; ignoring advisory metadata');
	}
	if (jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops) || jwk.key_ops.length !== 1 || jwk.key_ops[0] !== 'verify')) {
		log.warn('Expected public signature verification operations in JWK key_ops');
	}
	let publicJwk: JWK;
	let algorithms: string[];
	if (jwk.kty === 'EC') {
		const curve = typeof jwk.crv === 'string' && Object.prototype.hasOwnProperty.call(curves, jwk.crv) ? curves[jwk.crv] : undefined;
		if (!curve || decode(jwk.x).length !== curve.bytes || decode(jwk.y).length !== curve.bytes) {
			throw new Error('Invalid or unsupported EC key');
		}
		publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
		algorithms = [curve.alg];
	} else if (jwk.kty === 'RSA') {
		const modulus = decode(jwk.n);
		const exponent = decode(jwk.e);
		if (modulus.length > 1024 || exponent.length > 4) {
			log.warn('RSA key exceeds the usual modulus or exponent size');
		}
		if (
			modulus[0] === 0 ||
			exponent[0] === 0 ||
			!(modulus[modulus.length - 1] & 1) ||
			!(exponent[exponent.length - 1] & 1) ||
			(exponent.length === 1 && exponent[0] < 3)
		) {
			throw new Error('Invalid RSA public key');
		}
		publicJwk = { kty: jwk.kty, n: jwk.n, e: jwk.e };
		algorithms = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];
	} else if (jwk.kty === 'OKP' && (jwk.crv === 'Ed25519' || jwk.crv === 'Ed448')) {
		if (decode(jwk.x).length !== (jwk.crv === 'Ed25519' ? 32 : 57)) {
			throw new Error('Invalid Edwards public key');
		}
		publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x };
		algorithms = ['EdDSA'];
	} else {
		throw new Error('Unsupported public signing key');
	}
	if (jwk.alg !== undefined && (typeof jwk.alg !== 'string' || !/^[\x20-\x7e]+$/.test(jwk.alg))) {
		throw new Error('Invalid JWK algorithm');
	}
	const compatibleAlgorithm = jwk.alg !== undefined && algorithms.includes(jwk.alg);
	if (jwk.alg !== undefined && !compatibleAlgorithm) {
		log.warn('Unrecognized or incompatible JWK algorithm; omitting advisory algorithm metadata');
	}
	const key = createPublicKey({ key: publicJwk, format: 'jwk' });
	if (jwk.kty === 'RSA' && (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
		throw new Error('RSA keys must have at least 2048 bits');
	}
	return {
		...publicJwk,
		...(compatibleAlgorithm ? { alg: jwk.alg } : {}),
		...(jwk.ext !== undefined ? { ext: jwk.ext } : {}),
	};
}

/** iat and exp (required for JWT proofs) are added by the attestation signer. */
export function buildKeyAttestationPayload<T extends KeyAttestationOptions = KeyAttestationOptions>(
	keys: JWK[],
	nonce?: string,
	options?: T,
): JWTPayload {
	if (keys.length === 0) {
		throw new Error('Key attestations require at least one key');
	}
	return {
		...(options as KeyAttestationOptions | undefined),
		attested_keys: keys,
		...(nonce === undefined ? {} : { nonce }),
	};
}

/** Validation errors are safe to return without exposing submitted key material. */
export class AttestationRequestValidationError extends Error {
	constructor(readonly response: { error: string; message: string }) {
		super(response.message);
	}
}

export function parseKeyAttestationRequest(body: unknown): { keys: JWK[]; nonce: string } {
	const { jwks, openid4vci } = (body ?? {}) as { jwks?: unknown; openid4vci?: { nonce?: unknown } };
	if (!Array.isArray(jwks) || jwks.length === 0) {
		throw new AttestationRequestValidationError({
			error: 'INVALID_JWKS',
			message: "'jwks' JSON body parameter is missing or not type of 'array' or array is empty",
		});
	}
	const nonce = openid4vci?.nonce;
	if (typeof nonce !== 'string' || !nonce) {
		throw new AttestationRequestValidationError({
			error: 'INVALID_OPENID4VCI_NONCE_VALUE',
			message: "'openid4vci.nonce' JSON body parameter is missing or not type of 'string'",
		});
	}
	try {
		return { keys: jwks.map(validatePublicAttestationKey), nonce };
	} catch (err) {
		const validationError = new Error(err instanceof Error ? err.message : 'Unknown key validation error');
		log.warn({ err: validationError }, 'Invalid key attestation request');
		throw new AttestationRequestValidationError({
			error: 'INVALID_JWKS',
			message: 'Every key must be a valid supported public signing JWK',
		});
	}
}

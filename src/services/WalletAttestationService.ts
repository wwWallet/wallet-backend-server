import { AttestationRequestValidationError, validatePublicAttestationKey } from './KeyAttestationService';
import type { JWK, JWTPayload } from 'jose';

import type { WalletAttestationOptions } from './walletProviderAttestation/types';

/** The signer adds iat and exp; optional claims cannot replace the subject or key binding. */
export function buildWalletAttestationPayload<T extends WalletAttestationOptions = WalletAttestationOptions>(
	key: JWK,
	clientId: string,
	options?: T,
): JWTPayload {
	return {
		...(options as WalletAttestationOptions | undefined),
		sub: clientId,
		cnf: { jwk: key },
	};
}

export function parseWalletAttestationRequest(body: unknown): { key: JWK; clientId: string; authorizationServer: string } {
	const { jwks, openid4vci } = (body ?? {}) as {
		jwks?: unknown;
		openid4vci?: { client_id?: unknown; authorization_server?: unknown };
	};
	if (!Array.isArray(jwks) || jwks.length === 0) {
		throw new AttestationRequestValidationError({ error: 'INVALID_JWKS',
			message: "'jwks' JSON body parameter is missing or not type of 'array' or array is empty" });
	}
	let key: JWK;
	try {
		if (jwks.length !== 1) throw new Error('Expected exactly one wallet-instance key');
		key = validatePublicAttestationKey(jwks[0]);
	} catch {
		throw new AttestationRequestValidationError({ error: 'INVALID_JWK',
			message: "'jwks' must contain exactly one valid supported public signing JWK" });
	}
	const clientId = openid4vci?.client_id;
	if (typeof clientId !== 'string' || !clientId.trim()) {
		throw new AttestationRequestValidationError({ error: 'INVALID_OPENID4VCI_CLIENT_ID',
			message: "'openid4vci.client_id' must be a non-empty string" });
	}
	const authorizationServer = openid4vci?.authorization_server;
	if (typeof authorizationServer !== 'string' || !authorizationServer.trim()) {
		throw new AttestationRequestValidationError({ error: 'INVALID_OPENID4VCI_AUTHORIZATION_SERVER',
			message: "'openid4vci.authorization_server' must be a non-empty string" });
	}
	return { key, clientId, authorizationServer };
}

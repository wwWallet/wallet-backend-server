import { readFileSync } from 'fs';
import path from 'path';
import { SignJWT } from 'jose';
import type { JWTPayload } from 'jose';
import type { WalletProviderStatusReference } from '../entities/WalletProviderStatus.entity';
import { importPrivateKeyPem, getKeyAttestationCertificateChain } from '../util/util';
import { config } from '../../config';
import { logger } from '../logger';

const log = logger.child({ module: 'WalletProviderService' });

const keysDir = config.keysDir;
const walletProviderPrivateKeyPath = path.join(keysDir, 'wallet-provider.key');
const walletProviderCertificatePath = path.join(keysDir, 'wallet-provider.pem');
const caCertificatePath = path.join(keysDir, 'ca.pem');

type WalletProviderSigningMaterial = {
	privateKey: string;
	certificate: string;
};

type WalletProviderAttestationType = 'key-attestation+jwt' | 'oauth-client-attestation+jwt';

// These files are required at startup. Restart the server after changing them.
const signingMaterial: WalletProviderSigningMaterial = {
	privateKey: readFileSync(walletProviderPrivateKeyPath, 'utf-8'),
	certificate: readFileSync(walletProviderCertificatePath, 'utf-8'),
};
// Key attestation requires the CA file to be present, even though it is not used for signing.
readFileSync(caCertificatePath, 'utf-8');
log.info('Wallet provider signing material loaded');

/** The maintenance expiry is independent of the short-lived attestation JWT. */
export function buildWalletProviderStatusClaim(entry: WalletProviderStatusReference) {
	return {
		status: {
			status_list: {
				idx: entry.idx,
				uri: `${config.url.replace(/\/+$/, '')}/wallet-provider/api/status-lists/${entry.listId}`,
			},
		},
		exp: entry.maintenanceExpiresAt,
	};
}

async function signWalletProviderToken(
	token: SignJWT,
	type: WalletProviderAttestationType | 'statuslist+jwt',
	material: WalletProviderSigningMaterial,
): Promise<string> {
	const privateKey = await importPrivateKeyPem(material.privateKey, 'ES256');
	if (!privateKey) {
		throw new Error('Failed to import wallet provider private key');
	}
	return token
		.setProtectedHeader({
			alg: 'ES256',
			typ: type,
			x5c: getKeyAttestationCertificateChain(material.certificate),
		})
		.sign(privateKey);
}

export function signWalletProviderAttestation(payload: JWTPayload, type: WalletProviderAttestationType): Promise<string> {
	return signWalletProviderToken(new SignJWT(payload).setIssuedAt().setExpirationTime('15s'), type, signingMaterial);
}

/** Signs status lists without changing the caller's issued-at or expiry. */
export async function signWalletProviderStatusList(token: SignJWT): Promise<string> {
	return signWalletProviderToken(token, 'statuslist+jwt', signingMaterial);
}

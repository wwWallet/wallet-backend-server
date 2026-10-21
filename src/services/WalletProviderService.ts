import { readFile } from 'fs/promises';
import path from "path";
import { SignJWT } from "jose";
import type { JWTPayload } from "jose";
import type { WalletProviderStatusReference } from "../entities/WalletProviderStatus.entity";
import { importPrivateKeyPem, getKeyAttestationCertificateChain } from "../util/util";
import { config } from "../../config";

const keysDir = config.keysDir;
const walletProviderPrivateKeyPath = path.join(keysDir, 'wallet-provider.key');
const walletProviderCertificatePath = path.join(keysDir, 'wallet-provider.pem');
const caCertificatePath = path.join(keysDir, 'ca.pem');

export type WalletProviderSigningMaterial = {
	privateKey: string;
	certificate: string;
};

type WalletProviderAttestationType = 'key-attestation+jwt' | 'oauth-client-attestation+jwt';

/** Read fresh material on each request; KA also requires the CA file to be available. */
export async function loadWalletProviderSigningMaterial(requireCa = false): Promise<WalletProviderSigningMaterial> {
	const [privateKey, certificate] = await Promise.all([
		readFile(walletProviderPrivateKeyPath, 'utf-8'),
		readFile(walletProviderCertificatePath, 'utf-8'),
		...(requireCa ? [readFile(caCertificatePath, 'utf-8')] : []),
	]);
	return { privateKey, certificate };
}

loadWalletProviderSigningMaterial(true).then(() =>
	console.log("Test importing keys passed")
).catch((err) => {
	console.error(`Error imported wallet provider keys: ${err}`);
});

/** The maintenance expiry is independent of the short-lived attestation JWT. */
export function buildWalletProviderStatusClaim(entry: WalletProviderStatusReference) {
	return {
		status: {
			status_list: {
				idx: entry.idx,
				uri: `${config.url.replace(/\/+$/, '')}/wallet-provider/status-lists/${entry.listId}`,
			},
		},
		exp: entry.exp,
	};
}

async function signWalletProviderToken(
	token: SignJWT,
	type: WalletProviderAttestationType | 'statuslist+jwt',
	material: WalletProviderSigningMaterial,
): Promise<string> {
	return token.setProtectedHeader({
		alg: 'ES256',
		typ: type,
		x5c: getKeyAttestationCertificateChain(material.certificate),
	}).sign(await importPrivateKeyPem(material.privateKey, 'ES256'));
}

export function signWalletProviderAttestation(
	payload: JWTPayload,
	type: WalletProviderAttestationType,
	material: WalletProviderSigningMaterial,
): Promise<string> {
	return signWalletProviderToken(
		new SignJWT(payload)
			.setIssuedAt()
			.setExpirationTime('15s'),
			type,
			material
		);
}

/** Signs status lists without changing the caller's issued-at or expiry. */
export async function signWalletProviderStatus(token: SignJWT): Promise<string> {
	return signWalletProviderToken(token, 'statuslist+jwt', await loadWalletProviderSigningMaterial());
}

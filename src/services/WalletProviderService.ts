import { readFile } from 'fs/promises';
import path from "path";
import { SignJWT } from "jose";
import { importPrivateKeyPem, getKeyAttestationCertificateChain } from "../util/util";
import { config } from "../../config";

const keysDir = config.keysDir;
const walletProviderPrivateKeyPath = path.join(keysDir, 'wallet-provider.key');
const walletProviderCertificatePath = path.join(keysDir, 'wallet-provider.pem');
const caCertificatePath = path.join(keysDir, 'ca.pem');

Promise.all([
	readFile(walletProviderPrivateKeyPath, 'utf-8'),
	readFile(walletProviderCertificatePath, 'utf-8'),
	readFile(caCertificatePath, 'utf-8')
]).then(() =>
	console.log("Test importing keys passed")
).catch((err) => {
	console.error("Error imported wallet provider keys");
	console.error(err);
});

/** Signs status lists with the same provider identity as WIA/KA. */
export async function signWalletProviderStatus(token: SignJWT): Promise<string> {
	const [privateKey, certificate] = await Promise.all([
		readFile(walletProviderPrivateKeyPath, 'utf-8'),
		readFile(walletProviderCertificatePath, 'utf-8'),
	]);
	return token.setProtectedHeader({
		alg: 'ES256',
		typ: 'statuslist+jwt',
		x5c: getKeyAttestationCertificateChain(certificate),
	}).sign(await importPrivateKeyPem(privateKey, 'ES256'));
}

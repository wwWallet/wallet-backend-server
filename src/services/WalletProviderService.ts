import { readFile } from 'fs/promises';
import path from "path";
import { SignJWT } from "jose";
import { importPrivateKeyPem, getKeyAttestationCertificateChain } from "../util/util";
import { config } from "../../config";
import { Request, Response, NextFunction } from 'express';
import { timingSafeEqual } from 'node:crypto';

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

const forbidden = (res: Response) => {
	res.setHeader('WWW-Authenticate', 'Bearer');
	return res.status(403).send({
		error: 'forbidden',
		error_description: 'Missing or invalid bearer token',
	});
};

export const walletProviderStatusListRevokationBearerAuth = (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	// An unset secret disables operator revocation; it never permits anonymous access.
	if (!config.statusListRevokationBearerToken) {
		return forbidden(res);
	}
	const match = req.get('authorization')?.match(/^Bearer ([^\s]+)$/i);
	if (!match) {
		return forbidden(res);
	}

	const suppliedToken = Buffer.from(match[1]);
	const expectedToken = Buffer.from(config.statusListRevokationBearerToken);
	if (suppliedToken.length !== expectedToken.length || !timingSafeEqual(suppliedToken, expectedToken)) {
		return forbidden(res);
	}

	return next();
};

import { Router } from "express";
import { readFile } from 'fs/promises';
import path from "path";
import { importX509, SignJWT } from "jose";
import { importPrivateKeyPem, removeCertificateMarkers } from "../util/util";

const walletProviderRouter = Router();

const walletProviderPrivateKeyPath = path.join('/', 'app', 'keys', 'wallet-provider.key');
const walletProviderCertificatePath = path.join('/', 'app', 'keys', 'wallet-provider.pem');
const caCertificatePath = path.join('/', 'app', 'keys', 'ca.pem');


walletProviderRouter.post('/key-attestation/generate', async (req, res) => {

	console.log("Received body = ", req.body)
	const { jwks, openid4vci: { nonce } } = req.body;

	if (!jwks || !Array.isArray(jwks) || jwks.length == 0) {
		const errorResponse = {
			error: "INVALID_JWKS",
			message: "'jwks' JSON body parameter is missing or not type of 'array' or array is empty",
		};
		console.log(errorResponse);
		return res.status(400).send(errorResponse);
	}

	if (!nonce || typeof nonce !== 'string') {
		const errorResponse = {
			error: "INVALID_OPENID4VCI_NONCE_VALUE",
			message: "'openid4vci.nonce' JSON body parameter is missing or not type of 'string'",
		};
		console.log(errorResponse);
		return res.status(400).send(errorResponse);
	}

	let pemPrivateKey: string | null = null;
	let walletProviderCertificate: string | null = null;
	let caCertificate: string | null = null;

	try {
		[
			pemPrivateKey,
			walletProviderCertificate,
			caCertificate
		] = await Promise.all([
			readFile(walletProviderPrivateKeyPath, 'utf-8'),
			readFile(walletProviderCertificatePath, 'utf-8'),
			readFile(caCertificatePath, 'utf-8')
		]);
	}
	catch (err) {
		const errorResponse = {
			error: "UNSUPPORTED",
			message: "key attestation generation is not supported",
		};
		console.error(err);
		console.log(errorResponse);
		return res.status(400).send(errorResponse);
	}


	try {
		const keyAttestation = await new SignJWT({
			attested_keys: jwks,
			nonce: nonce,
		}).setIssuedAt()
			.setProtectedHeader({
				alg: 'ES256',
				typ: 'keyattestation+jwt',
				x5c: [
					removeCertificateMarkers(walletProviderCertificate)
				],
			})
			.setExpirationTime("15s")
			.sign(await importPrivateKeyPem(pemPrivateKey, 'ES256'))

		return res.send({ key_attestation: keyAttestation });
	}
	catch (err) {
		console.error(err);
		return res.status(400).send({
			error: "FAILED",
			message: "key attestation signature generation failed",
		});
	}
});

export {
	walletProviderRouter,
}

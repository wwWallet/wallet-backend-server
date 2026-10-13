import { Router } from "express";
import { readFile } from 'fs/promises';
import path from "path";
import { SignJWT } from "jose";
import type { JWK } from "jose";
import { importPrivateKeyPem, getKeyAttestationCertificateChain } from "../util/util";
import { config } from "../../config";
import { zeroStatusListReference } from "./wallet_provider_status_list.router";

type KeyAttestationRequestBody = {
	jwks: JWK[];
	openid4vci: {
		nonce: string;
	};
};

type WalletInstanceAttestationRequestBody = {
	/** Expected to contain exactly one public wallet-instance key. */
	jwks: JWK[];
	openid4vci: {
		client_id: string;
		authorization_server: string;
	};
};

const walletProviderRouter = Router();

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

walletProviderRouter.post('/key-attestation/generate', async (req, res) => {

	console.log("Received body = ", req.body)
	const { jwks, openid4vci: { nonce } }: KeyAttestationRequestBody = req.body;

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

	const keyStorageStatus = zeroStatusListReference();

	try {
		const keyAttestation = await new SignJWT({
			attested_keys: jwks,
			nonce: nonce,
			key_storage: ['iso_18045_basic'],
			user_authentication: ['iso_18045_basic'],
			certification: `${config.url ?? 'http://localhost:3000'}/certification`,
			key_storage_status: keyStorageStatus,
		}).setIssuedAt()
			.setProtectedHeader({
				alg: 'ES256',
				typ: 'key-attestation+jwt',
				x5c: getKeyAttestationCertificateChain(walletProviderCertificate),
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

walletProviderRouter.post('/wallet-instance-attestation/generate', async (req, res) => {
	const { jwks, openid4vci }: WalletInstanceAttestationRequestBody = req.body ?? {};

	if (!jwks || !Array.isArray(jwks) || jwks.length === 0) {
		return res.status(400).send({
			error: "INVALID_JWKS",
			message: "'jwks' JSON body parameter is missing or not type of 'array' or array is empty",
		});
	}

	const walletInstanceKey = jwks[0];
	if (!walletInstanceKey || typeof walletInstanceKey !== 'object' || Array.isArray(walletInstanceKey)) {
		return res.status(400).send({
			error: "INVALID_JWK",
			message: "'jwks[0]' must be the Wallet Unit proof-of-possession public JWK",
		});
	}

	const clientId = openid4vci?.client_id;
	if (typeof clientId !== 'string' || clientId.trim().length === 0) {
		return res.status(400).send({
			error: "INVALID_OPENID4VCI_CLIENT_ID",
			message: "'openid4vci.client_id' must be a non-empty string",
		});
	}

	const authorizationServer = openid4vci?.authorization_server;
	if (typeof authorizationServer !== 'string' || authorizationServer.trim().length === 0) {
		return res.status(400).send({
			error: "INVALID_OPENID4VCI_AUTHORIZATION_SERVER",
			message: "'openid4vci.authorization_server' must be a non-empty string",
		});
	}

	let pemPrivateKey: string;
	let walletProviderCertificate: string;

	try {
		[pemPrivateKey, walletProviderCertificate] = await Promise.all([
			readFile(walletProviderPrivateKeyPath, 'utf-8'),
			readFile(walletProviderCertificatePath, 'utf-8'),
		]);
	}
	catch (err) {
		console.error(err);
		return res.status(400).send({
			error: "UNSUPPORTED",
			message: "Wallet Instance Attestation generation is not supported",
		});
	}

	try {
		const clientStatus = zeroStatusListReference();

		const walletInstanceAttestation = await new SignJWT({
			sub: clientId,
			aud: authorizationServer,
			cnf: { jwk: walletInstanceKey },
			wallet_name: 'WE BUILD wwWallet',
			wallet_link: 'https://webuild.wwwallet.org',
			wallet_version: '1.0.0',
			wallet_solution_certification_information: 'Development instance — no wallet solution certification asserted',
			client_status: clientStatus,
		}).setIssuedAt()
			.setProtectedHeader({
				alg: 'ES256',
				typ: 'oauth-client-attestation+jwt',
				x5c: getKeyAttestationCertificateChain(walletProviderCertificate),
			})
			.setExpirationTime("15s")
			.sign(await importPrivateKeyPem(pemPrivateKey, 'ES256'));

		return res.send({ wallet_instance_attestation: walletInstanceAttestation });
	}
	catch (err) {
		console.error(err);
		return res.status(400).send({
			error: "FAILED",
			message: "Wallet Instance Attestation signature generation failed",
		});
	}
});

export {
	walletProviderRouter,
}

/** Use the same signing identity for the status list and its WIA/KA references. */
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

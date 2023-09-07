import express, { Request, Response, Router } from 'express';
import { SignJWT } from 'jose';
import * as uuid from 'uuid';
import crypto from 'node:crypto';
import * as SimpleWebauthn from '@simplewebauthn/server';
import base64url from 'base64url';

import config from '../../config';
import { NaturalPersonWallet } from '@gunet/ssi-sdk';
import { CreateUser, createUser, deleteWebauthnCredential, getUserByCredentials, getUserByDID, getUserByWebauthnCredential, newWebauthnCredentialEntity, updateUserByDID, UpdateUserErr, updateWebauthnCredential } from '../entities/user.entity';
import { jsonParseTaggedBinary, jsonStringifyTaggedBinary } from '../util/util';
import { AuthMiddleware } from '../middlewares/auth.middleware';
import { ChallengeErr, createChallenge, popChallenge } from '../entities/WebauthnChallenge.entity';
import * as webauthn from '../webauthn';
import * as scrypt from "../scrypt";


/**
 * "/user"
 */
const noAuthUserController: Router = express.Router();

const userController: Router = express.Router();
userController.use(AuthMiddleware);
noAuthUserController.use('/session', userController);

async function initNewUser(req: Request): Promise<{ fcmToken: Buffer, browserFcmToken: Buffer, keys: Buffer, did: string }> {
	const fcmToken = req.body.fcm_token ? Buffer.from(req.body.fcm_token) : Buffer.from("");
	const browserFcmToken = req.body.browser_fcm_token ? Buffer.from(req.body.browser_fcm_token) : Buffer.from("");
	const naturalPersonWallet: NaturalPersonWallet = await new NaturalPersonWallet().createWallet('ES256');
	return {
		fcmToken,
		browserFcmToken,
		keys: Buffer.from(JSON.stringify(naturalPersonWallet.key)),
		did: naturalPersonWallet.key.did,
	};
}

async function initSession(did: string, displayName: string): Promise<{ did: string, appToken: string, displayName: string }> {
	const secret = new TextEncoder().encode(config.appSecret);
	const appToken = await new SignJWT({ did })
		.setProtectedHeader({ alg: "HS256" })
		.sign(secret);
	return {
		did,
		appToken,
		displayName,
	};
}

noAuthUserController.post('/register', async (req: Request, res: Response) => {
	const username = req.body.username;
	const password = req.body.password;

	const passwordHash = await scrypt.createHash(password);
	const newUser: CreateUser = {
		...await initNewUser(req),
		username: username ? username : "",
		displayName: req.body.displayName,
		passwordHash: passwordHash,
		webauthnUserHandle: uuid.v4(),
	};

	const result = (await createUser(newUser));
	if (result.err) {
		console.log("Failed to create user")
		res.status(500).send({ error: result.val });
		return;
	}

	const user = result.unwrap();
	res.status(200).send(await initSession(user.did, user.displayName || username));
});

noAuthUserController.post('/login', async (req: Request, res: Response) => {
	const { username, password } = req.body;
	if (!username || !password) {
		res.status(500).send({ error: "No username or password was given" });
		return;
	}
	const userRes = await getUserByCredentials(username, password);
	if (userRes.err) {
		res.status(500).send({});
		return;
	}
	console.log('user res = ', userRes)
	const user = userRes.unwrap();
	res.status(200).send(await initSession(user.did, user.displayName || username));
})

noAuthUserController.post('/register-webauthn-begin', async (req: Request, res: Response) => {
	const challengeRes = await createChallenge("create", uuid.v4());
	if (challengeRes.err) {
		res.status(500).send({});
		return;
	}
	const challenge = challengeRes.unwrap();

	const createOptions = webauthn.makeCreateOptions({
		challenge: challenge.challenge,
		user: {
			webauthnUserHandle: challenge.userHandle,
			name: "",
			displayName: "",
		},
	});

	res.status(200).send(jsonStringifyTaggedBinary({
		challengeId: challenge.id,
		createOptions,
	}));
});

noAuthUserController.post('/register-webauthn-finish', async (req: Request, res: Response) => {
	console.log("webauthn register-finish", req.body);

	const challengeRes = await popChallenge(req.body.challengeId);
	if (challengeRes.err) {
		if ([ChallengeErr.EXPIRED, ChallengeErr.NOT_EXISTS].includes(challengeRes.val)) {
			res.status(404).send({});
		} else {
			res.status(500).send({});
		}
		return;
	}
	const challenge = challengeRes.unwrap();
	console.log("webauthn register-finish challenge", challenge);

	const credential = req.body.credential;
	const verification = await SimpleWebauthn.verifyRegistrationResponse({
		response: credential,
		expectedChallenge: base64url.encode(challenge.challenge),
		expectedOrigin: config.webauthn.origin,
		expectedRPID: config.webauthn.rp.id,
		requireUserVerification: true,
	});

	if (verification.verified) {
		const webauthnUserHandle = challenge.userHandle;
		if (!webauthnUserHandle) {
			res.status(500).send({});
			return;
		}

		const newUser: CreateUser = {
			...await initNewUser(req),
			displayName: req.body.displayName,
			webauthnUserHandle,
			webauthnCredentials: [
				newWebauthnCredentialEntity({
					credentialId: Buffer.from(verification.registrationInfo.credentialID),
					userHandle: Buffer.from(webauthnUserHandle),
					nickname: req.body.nickname,
					publicKeyCose: Buffer.from(verification.registrationInfo.credentialPublicKey),
					signatureCount: verification.registrationInfo.counter,
					transports: credential.response.transports || [],
					attestationObject: Buffer.from(verification.registrationInfo.attestationObject),
					create_clientDataJSON: Buffer.from(credential.response.clientDataJSON),
					prfCapable: credential.clientExtensionResults?.prf?.enabled || false,
				}),
			],
		};

		const userRes = await createUser(newUser, false, );
		if (userRes.ok) {
			console.log("Created user", userRes.val);
			res.status(200).send(await initSession(userRes.val.did, userRes.val.displayName));
		} else {
			res.status(500).send({});
		}
	} else {
		res.status(400).send({});
	}
})

noAuthUserController.post('/login-webauthn-begin', async (req: Request, res: Response) => {
	const challengeRes = await createChallenge("get");
	if (challengeRes.err) {
		res.status(500).send({});
		return;
	}
	const challenge = challengeRes.unwrap();
	const getOptions = webauthn.makeGetOptions({ challenge: challenge.challenge });

	res.status(200).send(jsonStringifyTaggedBinary({
		challengeId: challenge.id,
		getOptions,
	}));
});

noAuthUserController.post('/login-webauthn-finish', async (req: Request, res: Response) => {
	console.log("webauthn login-finish", req.body);

	const credential = req.body.credential;
	const userHandle = base64url.toBuffer(credential.response.userHandle).toString();
	const credentialId = base64url.toBuffer(credential.id);

	const userRes = await getUserByWebauthnCredential(userHandle, credentialId);
	if (userRes.err) {
		res.status(403).send({});
		return;
	}
	const [user, credentialRecord] = userRes.unwrap();

	const challengeRes = await popChallenge(req.body.challengeId);
	if (challengeRes.err) {
		if ([ChallengeErr.EXPIRED, ChallengeErr.NOT_EXISTS].includes(challengeRes.val)) {
			res.status(404).send({});
		} else {
			res.status(500).send({});
		}
		return;
	}
	const challenge = challengeRes.unwrap();

	console.log("webauthn login-finish challenge", challenge);

	const verification = await SimpleWebauthn.verifyAuthenticationResponse({
		response: credential,
		expectedChallenge: base64url.encode(challenge.challenge),
		expectedOrigin: config.webauthn.origin,
		expectedRPID: config.webauthn.rp.id,
		requireUserVerification: true,
		authenticator: {
			credentialID: credentialRecord.credentialId,
			credentialPublicKey: credentialRecord.publicKeyCose,
			counter: credentialRecord.signatureCount,
		},
	});

	if (verification.verified) {
		const updateCredentialRes = await updateWebauthnCredential(credentialRecord, (entity) => {
			entity.signatureCount = verification.authenticationInfo.newCounter;
			entity.lastUseTime = new Date();
			return entity;
		});

		if (updateCredentialRes.ok) {
			res.status(200).send({
				...await initSession(user.did, user.displayName),
				username: user.username,
			});
		} else {
			res.status(500).send({});
		}

	} else {
		res.status(400).send({});
	}
})

userController.get('/account-info', async (req: Request, res: Response) => {
	const userRes = await getUserByDID(req.user.did);
	if (userRes.err) {
		res.status(403).send({});
		return;
	}
	const user = userRes.unwrap();

	const keys = jsonParseTaggedBinary(user.keys.toString());

	res.status(200).send(jsonStringifyTaggedBinary({
		username: user.username,
		displayName: user.displayName,
		did: user.did,
		hasPassword: user.passwordHash !== null,
		publicKey: keys.publicKey,
		webauthnUserHandle: user.webauthnUserHandle,
		webauthnCredentials: (user.webauthnCredentials || []).map(cred => ({
			createTime: cred.createTime,
			credentialId: cred.credentialId,
			id: cred.id,
			lastUseTime: cred.lastUseTime,
			nickname: cred.nickname,
			prfCapable: cred.prfCapable,
		})),
	}));
})

userController.post('/webauthn/register-begin', async (req: Request, res: Response) => {
	const userRes = await updateUserByDID(req.user.did, (userEntity, manager) => {
		if (!userEntity.webauthnUserHandle) {
			userEntity.webauthnUserHandle = uuid.v4();
		}
		return userEntity;
	});

	if (userRes.err) {
		res.status(403).send({});
		return;
	}
	const user = userRes.unwrap();

	const prfSalt = crypto.randomBytes(32);
	const challengeRes = await createChallenge("create", user.webauthnUserHandle, prfSalt);
	if (challengeRes.err) {
		res.status(500).send({});
		return;
	}
	const challenge = challengeRes.unwrap();

	const createOptions = webauthn.makeCreateOptions({
		challenge: challenge.challenge,
		user: {
			...user,
			name: user.displayName,
		},
	});

	res.status(200).send(jsonStringifyTaggedBinary({
		username: user.username,
		challengeId: challenge.id,
		createOptions,
	}));
});

userController.post('/webauthn/register-finish', async (req: Request, res: Response) => {
	console.log("webauthn register-finish", req.body);

	const userRes = await getUserByDID(req.user.did);
	if (userRes.err) {
		res.status(403).send({});
		return;
	}
	const user = userRes.unwrap();

	const challengeRes = await popChallenge(req.body.challengeId);
	if (challengeRes.err) {
		if ([ChallengeErr.EXPIRED, ChallengeErr.NOT_EXISTS].includes(challengeRes.val)) {
			res.status(404).send({});
		} else {
			res.status(500).send({});
		}
		return;
	}
	const challenge = challengeRes.unwrap();

	console.log("webauthn register-finish challenge", challenge);

	const credential = req.body.credential;
	const verification = await SimpleWebauthn.verifyRegistrationResponse({
		response: credential,
		expectedChallenge: base64url.encode(challenge.challenge),
		expectedOrigin: config.webauthn.origin,
		expectedRPID: config.webauthn.rp.id,
	});

	if (verification.verified) {
		const updateUserRes = await updateUserByDID(user.did, (userEntity, manager) => {
			userEntity.webauthnCredentials = userEntity.webauthnCredentials || [];
			userEntity.webauthnCredentials.push(
				newWebauthnCredentialEntity({
					credentialId: Buffer.from(verification.registrationInfo.credentialID),
					userHandle: Buffer.from(userEntity.webauthnUserHandle),
					nickname: req.body.nickname,
					publicKeyCose: Buffer.from(verification.registrationInfo.credentialPublicKey),
					signatureCount: verification.registrationInfo.counter,
					transports: credential.response.transports || [],
					attestationObject: Buffer.from(verification.registrationInfo.attestationObject),
					create_clientDataJSON: Buffer.from(credential.response.clientDataJSON),
					prfCapable: credential.clientExtensionResults?.prf?.enabled || false,
				}, manager)
			);
			return userEntity;
		});

		if (updateUserRes.ok) {
			res.status(200).send(jsonStringifyTaggedBinary({
				credentialId: credential.id
			}));
		} else {
			res.status(500).send({});
		}

	} else {
		res.status(400).send({});
	}
})

userController.delete('/webauthn/credential/:id', async (req: Request, res: Response) => {
	console.log("webauthn delete", req.params.id);

	const userRes = await getUserByDID(req.user.did);
	if (userRes.err) {
		res.status(403).send({});
		return;
	}
	const user = userRes.unwrap();

	const deleteRes = await deleteWebauthnCredential(user, req.params.id);
	if (deleteRes.ok) {
		res.status(204).send();
	} else {
		if (deleteRes.val === UpdateUserErr.NOT_EXISTS) {
			res.status(404).send();
		} else {
			res.status(500).send();
		}
	}
})


// /**
//  * expect 'alg' query parameter
//  */
// userController.get('/keys/public', AuthMiddleware, async (req: Request, res: Response) => {
// 	const did = req.user?.did;
// 	const algorithm = req.query["alg"] as string;
// 	if (did == undefined) {
// 		res.status(401).send({ err: 'UNAUTHORIZED' });
// 		return;
// 	}
// 	const alg: SigningAlgorithm = algorithm as SigningAlgorithm;
// 	const result = await getPublicKey(did, algorithm as SigningAlgorithm);
// 	if (!result) {
// 		res.status(500).send();
// 		return;
// 	}
// 	const { publicKeyJwk } = result;

// 	res.send({ publicKeyJwk });
// });

export default noAuthUserController;

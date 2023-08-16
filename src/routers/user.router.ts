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


/**
 * "/user"
 */
const noAuthUserController: Router = express.Router();

const userController: Router = express.Router();
userController.use(AuthMiddleware);
noAuthUserController.use('/session', userController);


noAuthUserController.post('/register', async (req: Request, res: Response) => {
	const username = req.body.username;	
	const password = req.body.password;
	const fcm_token = req.body.fcm_token;
	const browser_fcm_token = req.body.browser_fcm_token;
	if (!username || !password) {
		res.status(500).send({ error: "No username or password was given" });
		return;
	}
	const naturalPersonWallet: NaturalPersonWallet = await new NaturalPersonWallet().createWallet('ES256');

	const passwordHash = crypto.createHash('sha256').update(password).digest('base64');
	const keysStringified = JSON.stringify(naturalPersonWallet.key);
	const newUser: CreateUser = {
		username: username ? username : "", 
		passwordHash: passwordHash,
		keys: Buffer.from(keysStringified),
		did: naturalPersonWallet.key.did,
		fcmToken: fcm_token ? Buffer.from(fcm_token) : Buffer.from(""),
		browserFcmToken: browser_fcm_token ? Buffer.from(browser_fcm_token) : Buffer.from(""),
		webauthnUserHandle: uuid.v4(),
	};

	const result = (await createUser(newUser));
	if (result.err) {
		console.log("Failed to create user")
		res.status(500).send({ error: result.val });
		return;
	}


	const secret = new TextEncoder().encode(config.appSecret);
	const appToken = await new SignJWT({ did: naturalPersonWallet.key.did })
		.setProtectedHeader({ alg: "HS256" }) 
		.sign(secret);

	res.status(200).send({ did: naturalPersonWallet.key.did, appToken });
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
	const { did } = user;
	const secret = new TextEncoder().encode(config.appSecret);
	const appToken = await new SignJWT({ did })
		.setProtectedHeader({ alg: "HS256" })
		.sign(secret);

	res.status(200).send({ did: user.did, appToken: appToken });
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
			const { did } = user;
			const secret = new TextEncoder().encode(config.appSecret);
			const appToken = await new SignJWT({ did })
				.setProtectedHeader({ alg: "HS256" })
				.sign(secret);

			res.status(200).send({
				username: user.username,
				did: user.did,
				appToken: appToken,
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
	const userRes = await getUserByDID(req.user.did);
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
			name: user.username,
			displayName: user.username,
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
				newWebauthnCredentialEntity(manager, {
					credentialId: Buffer.from(verification.registrationInfo.credentialID),
					userHandle: Buffer.from(userEntity.webauthnUserHandle),
					nickname: req.body.nickname,
					publicKeyCose: Buffer.from(verification.registrationInfo.credentialPublicKey),
					signatureCount: verification.registrationInfo.counter,
					transports: credential.response.transports || [],
					attestationObject: Buffer.from(verification.registrationInfo.attestationObject),
					create_clientDataJSON: Buffer.from(credential.response.clientDataJSON),
					prfCapable: credential.clientExtensionResults?.prf?.enabled || false,
				})
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

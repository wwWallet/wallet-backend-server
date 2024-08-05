import express, { Request, Response, Router } from 'express';
import { SignJWT } from 'jose';
import * as uuid from 'uuid';
import crypto from 'node:crypto';
import * as SimpleWebauthn from '@simplewebauthn/server';
import base64url from 'base64url';
import { EntityManager } from "typeorm"

import config from '../../config';
import { CreateUser, createUser, deleteUserByDID, deleteWebauthnCredential, getUserByCredentials, getUserByDID, getUserByWebauthnCredential, GetUserErr, newWebauthnCredentialEntity, privateDataEtag, updateUserByDID, UpdateUserErr, updateWebauthnCredential, updateWebauthnCredentialById, UserEntity } from '../entities/user.entity';
import { checkedUpdate, EtagUpdate, jsonParseTaggedBinary } from '../util/util';
import { AuthMiddleware } from '../middlewares/auth.middleware';
import { ChallengeErr, createChallenge, popChallenge } from '../entities/WebauthnChallenge.entity';
import * as webauthn from '../webauthn';
import * as scrypt from "../scrypt";
import { appContainer } from '../services/inversify.config';
import { RegistrationParams, WalletKeystoreManager } from '../services/interfaces';
import { TYPES } from '../services/types';
import { runTransaction } from '../entities/common.entity';
import { deleteAllFcmTokensForUser, FcmTokenEntity } from '../entities/FcmToken.entity';
import { deleteAllPresentationsWithHolderDID } from '../entities/VerifiablePresentation.entity';
import { deleteAllCredentialsWithHolderDID } from '../entities/VerifiableCredential.entity';
import { Err, Ok, Result } from 'ts-results';



const walletKeystoreManagerService = appContainer.get<WalletKeystoreManager>(TYPES.WalletKeystoreManagerService);

/**
 * "/user"
 */
const noAuthUserController: Router = express.Router();

const userController: Router = express.Router();
userController.use(AuthMiddleware);
noAuthUserController.use('/session', userController);


async function initSession(user: UserEntity): Promise<{
	id: number,
	did: string,
	appToken: string,
	username?: string,
	displayName: string,
	privateData: Buffer,
	webauthnRpId: string,
	webauthnUserHandle: string,
}> {
	const secret = new TextEncoder().encode(config.appSecret);
	const appToken = await new SignJWT({ did: user.did })
		.setProtectedHeader({ alg: "HS256" })
		.sign(secret);
	return {
		id: user.id,
		appToken,
		did: user.did,
		displayName: user.displayName || user.username,
		privateData: user.privateData,
		username: user.username,
		webauthnRpId: webauthn.getRpId(),
		webauthnUserHandle: user.webauthnUserHandle,
	};
}

noAuthUserController.post('/register', async (req: Request, res: Response) => {
	const username = req.body.username;
	const password = req.body.password;
	if (!username || !password) {
		res.status(500).send({ error: "No username or password was given" });
		return;
	}

	const walletInitializationResult = await walletKeystoreManagerService.initializeWallet(
		{ ...req.body as RegistrationParams }
	);

	if (walletInitializationResult.err) {
		return res.status(400).send({ error: walletInitializationResult.val })
	}

	const passwordHash = await scrypt.createHash(password);
	const newUser: CreateUser = {
		...walletInitializationResult.unwrap(),
		username: username ? username : "",
		passwordHash: passwordHash,
		webauthnUserHandle: uuid.v4(),
	};

	const result = (await createUser(newUser));
	if (result.ok) {
		res.status(200)
			.header({ 'X-Private-Data-ETag': privateDataEtag(result.val.privateData) })
			.send(await initSession(result.val));

	} else {
		console.log("Failed to create user")
		res.status(500).send({ error: result.val });
	}
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
	res.status(200)
		.header({ 'X-Private-Data-ETag': privateDataEtag(user.privateData) })
		.send(await initSession(user));
})

noAuthUserController.post('/register/db-keys', async (req: Request, res: Response) => {
})

noAuthUserController.post('/login/db-keys', async (req: Request, res: Response) => {

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

	res.status(200).send({
		challengeId: challenge.id,
		createOptions,
	});
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
		response: {
			type: credential.type,
			id: credential.id,
			rawId: credential.id, // SimpleWebauthn requires this base64url encoded
			response: {
				attestationObject: base64url.encode(credential.response.attestationObject),
				clientDataJSON: base64url.encode(credential.response.clientDataJSON),
			},
			clientExtensionResults: credential.clientExtensionResults,
		},
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
		const walletInitializationResult = await walletKeystoreManagerService.initializeWallet(
			{ ...req.body as RegistrationParams }
		);

		if (walletInitializationResult.err) {
			return res.status(400).send({ error: walletInitializationResult.val })
		}

		const newUser: CreateUser = {
			...walletInitializationResult.unwrap(),
			webauthnUserHandle,
			webauthnCredentials: [
				newWebauthnCredentialEntity({
					credentialId: credential.rawId,
					userHandle: Buffer.from(webauthnUserHandle),
					nickname: req.body.nickname,
					publicKeyCose: Buffer.from(verification.registrationInfo.credentialPublicKey),
					signatureCount: verification.registrationInfo.counter,
					transports: credential.response.transports || [],
					attestationObject: credential.response.attestationObject,
					create_clientDataJSON: credential.response.clientDataJSON,
					prfCapable: credential.clientExtensionResults?.prf?.enabled || false,
				}),
			],
		};

		const userRes = await createUser(newUser, false,);
		if (userRes.ok) {
			console.log("Created user", userRes.val);
			res.status(200)
				.header({ 'X-Private-Data-ETag': privateDataEtag(userRes.val.privateData) })
				.send(await initSession(userRes.val));
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

	res.status(200).send({
		challengeId: challenge.id,
		getOptions,
	});
});

noAuthUserController.post('/login-webauthn-finish', async (req: Request, res: Response) => {
	console.log("webauthn login-finish", req.body);

	const credential = req.body.credential;
	const userHandle = credential.response.userHandle.toString();
	const credentialId = credential.rawId;

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
		response: {
			type: credential.type,
			id: credential.id,
			rawId: credential.id, // SimpleWebauthn requires this base64url encoded
			response: {
				authenticatorData: base64url.encode(credential.response.authenticatorData),
				clientDataJSON: base64url.encode(credential.response.clientDataJSON),
				signature: base64url.encode(credential.response.signature),
			},
			clientExtensionResults: credential.clientExtensionResults,
		},
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
			res.status(200)
				.header({ 'X-Private-Data-ETag': privateDataEtag(user.privateData) })
				.send(await initSession(user));
		} else {
			res.status(500).send({});
		}

	} else {
		res.status(400).send({});
	}
})


userController.post('/fcm_token/add', async (req: Request, res: Response) => {
	const userDID = req.user.did;
	updateUserByDID(userDID, (userEntity, manager) => {
		if (req.body.fcm_token &&
			req.body.fcm_token != '' &&
			userEntity.fcmTokenList.filter((fcmTokenEntity) => fcmTokenEntity.value == req.body.fcm_token).length == 0) {
			const fcmTokenEntity = new FcmTokenEntity();
			fcmTokenEntity.user = userEntity;
			fcmTokenEntity.value = req.body.fcm_token;
			manager.save(fcmTokenEntity).then((result) => {
				userEntity.fcmTokenList.push(result);
			});
		}
		return userEntity;
	});
	res.status(200).send({});
})

userController.get('/account-info', async (req: Request, res: Response) => {
	const userRes = await getUserByDID(req.user.did);
	if (userRes.err) {
		res.status(403).send({});
		return;
	}
	const user = userRes.unwrap();

	const keys = jsonParseTaggedBinary(user.keys.toString());

	res.status(200).send({
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
	});
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

	res.status(200).send({
		username: user.username,
		challengeId: challenge.id,
		createOptions,
	});
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
		response: {
			type: credential.type,
			id: credential.id,
			rawId: credential.id, // SimpleWebauthn requires this base64url encoded
			response: {
				attestationObject: base64url.encode(credential.response.attestationObject),
				clientDataJSON: base64url.encode(credential.response.clientDataJSON),
			},
			clientExtensionResults: credential.clientExtensionResults,
		},
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

			const newPrivateData = checkedUpdate(
				req.headers['x-private-data-if-match'],
				privateDataEtag,
				{
					currentValue: userEntity.privateData,
					newValue: req.body.privateData,
				},
			);
			if (newPrivateData.ok) {
				userEntity.privateData = newPrivateData.val;
			} else {
				return Err(UpdateUserErr.PRIVATE_DATA_CONFLICT);
			}

			return userEntity;
		});

		if (updateUserRes.ok) {
			res.status(200)
				.header({ 'X-Private-Data-ETag': privateDataEtag(updateUserRes.val.privateData) })
				.send({ credentialId: credential.id });
		} else if (updateUserRes.val === UpdateUserErr.PRIVATE_DATA_CONFLICT) {
			res.status(412)
				.header({ 'X-Private-Data-ETag': privateDataEtag(user.privateData) })
				.send({});
		} else {
			res.status(500).send({});
		}

	} else {
		res.status(400).send({});
	}
})

userController.post('/webauthn/credential/:id/rename', async (req: Request, res: Response) => {
	console.log("webauthn rename", req.params.id);

	const updateRes = await updateWebauthnCredentialById(req.user.did, req.params.id, (credentialEntity, manager) => {
		credentialEntity.nickname = req.body.nickname || null;
		return credentialEntity;
	});

	if (updateRes.ok) {
		res.status(204).send();

	} else {
		if (updateRes.val === UpdateUserErr.NOT_EXISTS) {
			res.status(404).send();

		} else {
			res.status(500).send();
		}
	}
})

userController.post('/webauthn/credential/:id/delete', async (req: Request, res: Response) => {
	console.log("webauthn delete", req.params.id);

	const userRes = await getUserByDID(req.user.did);
	if (userRes.err) {
		res.status(403).send({});
		return;
	}
	const user = userRes.unwrap();

	const updatePrivateData: EtagUpdate<Buffer> = {
		expectTag: req.headers['x-private-data-if-match'] as string,
		newValue: req.body.privateData,
	};
	const deleteRes = await deleteWebauthnCredential(user, req.params.id, updatePrivateData);
	if (deleteRes.ok) {
		res.status(204)
			.header({ 'X-Private-Data-ETag': privateDataEtag(updatePrivateData.newValue) })
			.send();
	} else {
		if (deleteRes.val === UpdateUserErr.NOT_EXISTS) {
			res.status(404).send();

		} else if (deleteRes.val === UpdateUserErr.LAST_WEBAUTHN_CREDENTIAL) {
			res.status(409).send();

		} else if (deleteRes.val === UpdateUserErr.PRIVATE_DATA_CONFLICT) {
			res.status(412)
				.header({ 'X-Private-Data-ETag': privateDataEtag(updatePrivateData.newValue) })
				.send();

		} else {
			res.status(500).send();
		}
	}
})

userController.post('/private-data', async (req: Request, res: Response) => {
	const updateUserRes = await updateUserByDID(req.user.did, userEntity => {
		const newPrivateData = checkedUpdate(
			req.headers['x-private-data-if-match'],
			privateDataEtag,
			{
				currentValue: userEntity.privateData,
				newValue: req.body,
			},
		);
		if (newPrivateData.ok) {
			userEntity.privateData = newPrivateData.val;
			return Ok(userEntity);
		} else {
			return Err([UpdateUserErr.PRIVATE_DATA_CONFLICT, userEntity]);
		}
	});

	if (updateUserRes.ok) {
		res.status(204)
			.header({ 'X-Private-Data-ETag': privateDataEtag(updateUserRes.val.privateData) })
			.send();
	} else {
		if (updateUserRes.val === UpdateUserErr.NOT_EXISTS) {
			res.status(404).send();

		} else if (updateUserRes.val[0] === UpdateUserErr.PRIVATE_DATA_CONFLICT) {
			res.status(412)
				.header({ 'X-Private-Data-ETag': privateDataEtag(updateUserRes.val[1].privateData) })
				.send();

		} else {
			res.status(500).send();
		}
	}
});

userController.get('/private-data', async (req: Request, res: Response) => {
	const userRes = await getUserByDID(req.user.did);
	if (userRes.ok) {
		const privateData = userRes.val.privateData;
		res.status(200)
			.header({ 'X-Private-Data-ETag': privateDataEtag(privateData) })
			.send({ privateData });
	} else {
		if (userRes.val === GetUserErr.NOT_EXISTS) {
			res.status(404).send();

		} else {
			res.status(500).send();
		}
	}
});

userController.delete('/', async (req: Request, res: Response) => {
	const userDID = req.user.did;
	try {
		await runTransaction(async (entityManager: EntityManager) => {
			// Note: this executes all four branches before checking if any failed.
			// ts-results does not seem to provide an async-optimized version of Result.all(),
			// and it turned out nontrivial to write one that preserves the Ok and Err types like Result.all() does.
			return Result.all(
				await deleteAllFcmTokensForUser(userDID, { entityManager }),
				await deleteAllCredentialsWithHolderDID(userDID, { entityManager }),
				await deleteAllPresentationsWithHolderDID(userDID, { entityManager }),
				await deleteUserByDID(userDID, { entityManager }),
			);
		});

		return res.send({ result: "DELETED" });
	} catch (e) {
		return res.status(400).send({ result: e })
	}
});

export default noAuthUserController;

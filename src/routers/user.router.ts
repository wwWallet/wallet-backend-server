import express, { Request, Response, Router } from 'express';
import * as uuid from 'uuid';
import crypto from 'node:crypto';
import * as SimpleWebauthn from '@simplewebauthn/server';
import base64url from 'base64url';
import { EntityManager } from "typeorm"

import { config } from '../../config';
import { CreateUser, createUser, deleteUser, deleteWebauthnCredential, getUserByCredentials, getUser, getUserByWebauthnCredential, GetUserErr, newWebauthnCredentialEntity, privateDataEtag, updateUser, UpdateUserErr, updateWebauthnCredential, updateWebauthnCredentialById, UserEntity, UserId } from '../entities/user.entity';
import { checkedUpdate, EtagUpdate, jsonParseTaggedBinary } from '../util/util';
import { AuthMiddleware, createAppToken } from '../middlewares/auth.middleware';
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
	uuid: UserId,
	appToken: string,
	username?: string,
	displayName: string,
	privateData: Buffer,
	webauthnRpId: string,
}> {
	return {
		uuid: user.uuid,
		appToken: await createAppToken(user),
		displayName: user.displayName || user.username,
		privateData: user.privateData,
		username: user.username,
		webauthnRpId: webauthn.getRpId(),
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
	const userId = UserId.generate();
	const challengeRes = await createChallenge("create", userId);
	if (challengeRes.err) {
		res.status(500).send({});
		return;
	}
	const challenge = challengeRes.unwrap();

	const createOptions = webauthn.makeCreateOptions({
		challenge: challenge.challenge,
		user: {
			uuid: userId,
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
				attestationObject: base64url.encode(
					// Remove the attestation statement, so that for example expired
					// attestation certs don't cause the registration to fail.
					// We only want the attestation for informational purposes, such as
					// being able to monitor vulnerability reports and warn affected
					// users; we don't actually care whether the attestation is valid.
					webauthn.stripAttestationStatement(credential.response.attestationObject)
				),
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
		if (!challenge.userId) {
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
			uuid: challenge.userId,
			webauthnCredentials: [
				newWebauthnCredentialEntity({
					credentialId: credential.rawId,
					_userHandle: challenge.userId.asUserHandle(),
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
	const userId = UserId.fromUserHandle(credential.response.userHandle);
	const credentialId = credential.rawId;

	const userRes = await getUserByWebauthnCredential(userId, credentialId);
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

	let verification;
	try {
		verification = await SimpleWebauthn.verifyAuthenticationResponse({
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
	} catch (e) {
		console.log(e);
		return res.status(400).send({});
	}

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
	updateUser(req.user.id, (userEntity, manager) => {
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
	const userRes = await getUser(req.user.id);
	if (userRes.err) {
		res.status(403).send({});
		return;
	}
	const user = userRes.unwrap();

	res.status(200).send({
		uuid: user.uuid,
		username: user.username,
		displayName: user.displayName,
		hasPassword: user.passwordHash !== null,
		settings: {
			openidRefreshTokenMaxAgeInSeconds: user.openidRefreshTokenMaxAgeInSeconds,
		},
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
	const userRes = await getUser(req.user.id);

	if (userRes.err) {
		res.status(403).send({});
		return;
	}
	const user = userRes.unwrap();

	const prfSalt = crypto.randomBytes(32);
	const challengeRes = await createChallenge("create", user.uuid, prfSalt);
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

	const userRes = await getUser(req.user.id);
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
	let verification;
	try {
		verification = await SimpleWebauthn.verifyRegistrationResponse({
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
	} catch(e) {
		console.log(e);
		return res.status(400).send({error: "Registration response could not be verified"})
	}

	if (verification.verified) {
		const updateUserRes = await updateUser(user.uuid, (userEntity, manager) => {
			userEntity.webauthnCredentials = userEntity.webauthnCredentials || [];
			userEntity.webauthnCredentials.push(
				newWebauthnCredentialEntity({
					credentialId: Buffer.from(verification.registrationInfo.credentialID),
					_userHandle: user.uuid.asUserHandle(),
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

	const updateRes = await updateWebauthnCredentialById(req.user.id, req.params.id, (credentialEntity, manager) => {
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

	const userRes = await getUser(req.user.id);
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
	const updateUserRes = await updateUser(req.user.id, userEntity => {
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
	const userRes = await getUser(req.user.id);
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
	try {
		await runTransaction(async (entityManager: EntityManager) => {
			// Note: this executes all four branches before checking if any failed.
			// ts-results does not seem to provide an async-optimized version of Result.all(),
			// and it turned out nontrivial to write one that preserves the Ok and Err types like Result.all() does.
			return Result.all(
				await deleteAllFcmTokensForUser(req.user.id, { entityManager }),
				await deleteAllCredentialsWithHolderDID(req.user.did, { entityManager }),
				await deleteAllPresentationsWithHolderDID(req.user.did, { entityManager }),
				await deleteUser(req.user.id, { entityManager }),
			);
		});

		return res.send({ result: "DELETED" });
	} catch (e) {
		return res.status(400).send({ result: e })
	}
});


userController.post('/settings', async (req: Request, res: Response) => {
	try {
		const {
			openidRefreshTokenMaxAgeInSeconds
		} = req.body;
		const userRes = await getUser(req.user.id);

		if (userRes.ok) {
			const user = userRes.unwrap();
			await updateUser(user.uuid, (userEntity, manager) => {
				userEntity.openidRefreshTokenMaxAgeInSeconds = openidRefreshTokenMaxAgeInSeconds;
				manager.save(userEntity);
				return userEntity;
			})
			return res.send({ openidRefreshTokenMaxAgeInSeconds: user.openidRefreshTokenMaxAgeInSeconds })
		}
		return res.status(400).send({ error: userRes.err });
	}
	catch (err) {
		return res.status(500).send({ error: err });
	}
});

export default noAuthUserController;

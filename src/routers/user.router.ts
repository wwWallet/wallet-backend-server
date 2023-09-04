import express, { Request, Response, Router } from 'express';
import { SignJWT } from 'jose';
import config from '../../config';
import { NaturalPersonWallet } from '@gunet/ssi-sdk';
import { CreateUser, createUser, getUserByCredentials, UserEntity } from '../entities/user.entity';
import crypto from 'node:crypto';


/**
 * "/user"
 */
const userController: Router = express.Router();


userController.post('/register', async (req: Request, res: Response) => {
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
		browserFcmToken: browser_fcm_token ? Buffer.from(browser_fcm_token) : Buffer.from("")
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

userController.post('/login', async (req: Request, res: Response) => {
	const { username, password } = req.body;
	if (!username || !password) {
		res.status(500).send({ error: "No username or password was given" });
		return;
	}
	const userRes = await getUserByCredentials(username, password);
	if (userRes.err) {
		res.send(500).send({});
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

export default userController;

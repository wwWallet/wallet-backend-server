import express, { Request, Response, Router } from 'express';
import { SignJWT } from 'jose';
import config from '../../config';
import { CreateUser, createUser, getUserByCredentials } from '../entities/user.entity';
import crypto from 'node:crypto';


/**
 * "/user"
 */
const userController: Router = express.Router();


userController.post('/register', async (req: Request, res: Response) => {
	const {
		username,
		password,
		fcm_token,
		browser_fcm_token,
		keys,
		pbkdf2Params,
		privateData,
	} = req.body;
	if (!username || !password) {
		res.status(500).send({ error: "No username or password was given" });
		return;
	}
	const passwordHash = crypto.createHash('sha256').update(password).digest('base64');
	const keysStringified = JSON.stringify(keys);
	const newUser: CreateUser = {
		username: username ? username : "", 
		passwordHash: passwordHash,
		keys: Buffer.from(keysStringified),
		did: keys.did,
		fcmToken: fcm_token ? Buffer.from(fcm_token) : Buffer.from(""),
		browserFcmToken: browser_fcm_token ? Buffer.from(browser_fcm_token) : Buffer.from(""),
		pbkdf2Params,
		privateData: Buffer.from(privateData),
	};

	const result = (await createUser(newUser));
	if (result.err) {
		console.log("Failed to create user")
		res.status(500).send({ error: result.val });
		return;
	}


	const secret = new TextEncoder().encode(config.appSecret);
	const appToken = await new SignJWT({ did: keys.did })
		.setProtectedHeader({ alg: "HS256" }) 
		.sign(secret);

	res.status(200).send({ appToken });
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

	res.status(200).send({
		appToken,
		pbkdf2Params: user.pbkdf2Params,
		privateData: new TextDecoder().decode(user.privateData),
	});
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

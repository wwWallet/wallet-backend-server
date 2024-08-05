import { Request, Response, NextFunction } from "express";

import { jwtVerify } from 'jose';
import config from "../../config";
import { getUserByDID } from "../entities/user.entity";

export type AppTokenUser = {
	username: string;
	did: string;
}

async function verifyApptoken(jwt: string): Promise<{valid: boolean, payload: any}> {
	const secret = new TextEncoder().encode(config.appSecret);
	try {
		const { payload, protectedHeader } = await jwtVerify(jwt, secret);
		return { valid: true, payload: payload };
	}
	catch (err) {
		console.log('Signature verification failed');
		return { valid: false, payload: {}}
	}
}

export function AuthMiddleware(req: Request, res: Response, next: NextFunction) {
	let token: string;
	const authorizationHeader = req.headers.authorization;
	console.log("Authorization header = ", authorizationHeader)
	if (req.headers != undefined && authorizationHeader != undefined) {
		if (authorizationHeader.split(' ')[0] !== 'Bearer') {
			res.status(401).send();
			return;
		}
		token = authorizationHeader.split(' ')[1];
	}
	else {
		console.log("Unauthorized access to token: ", authorizationHeader?.split(' ')[1]);
		res.status(401).send(); // Unauthorized
		return;
	}

	verifyApptoken(token).then(async ({valid, payload}) => {
		if (valid === false) {
			console.log("Unauthorized access to ", token);
			res.status(401).send(); // Unauthorized
			return;
		}

		// success
		req.user = {
			username: "",
			did: ""
		} as AppTokenUser;
		req.user.did = (payload as AppTokenUser).did;
		const userRes = await getUserByDID(req.user.did);
		if (userRes.err) {
			res.status(401).send(); // Unauthorized
			return;
		}
		const user = userRes.unwrap();
		req.user.username = user.username;
		req.user.did = user.did;
		return next();
	})
	.catch(e => {
		console.log("Unauthorized access to ", token);
		res.status(401).send(); // Unauthorized
		return;
	});
}

import { Request, Response, NextFunction } from "express";

import { jwtVerify, SignJWT } from 'jose';
import config from "../../config";
import { getUserByDID, UserEntity } from "../entities/user.entity";

type AppTokenPayload = {
	did: string;
}

export type AppTokenUser = {
	username: string;
	did: string;
}

export async function createAppToken(user: UserEntity): Promise<string> {
	const secret = new TextEncoder().encode(config.appSecret);
	const payload: AppTokenPayload = { did: user.did };
	return await new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256" })
		.sign(secret);
}

async function verifyApptoken(jwt: string): Promise<AppTokenPayload | false> {
	const secret = new TextEncoder().encode(config.appSecret);
	try {
		const { payload, protectedHeader } = await jwtVerify(jwt, secret);
		return payload as AppTokenPayload;
	}
	catch (err) {
		console.log('Signature verification failed');
		return false;
	}
}

export function AuthMiddleware(req: Request, res: Response, next: NextFunction) {
	const authorizationHeader = req.headers?.authorization;
	console.log("Authorization header = ", authorizationHeader)
	if (authorizationHeader?.substring(0, 7) !== 'Bearer ') {
		console.log("Invalid authorization header:", authorizationHeader);
		res.status(401).send();
		return;
	}

	let token: string = authorizationHeader.substring(7);

	verifyApptoken(token).then(async (payload) => {
		if (!payload) {
			console.log("Unauthorized access to ", token);
			res.status(401).send(); // Unauthorized
			return;
		}

		const { did } = payload;
		const userRes = await getUserByDID(did);
		if (userRes.ok) {
			req.user = {
				username: userRes.val.username,
				did,
			};
			return next();
		}

		res.status(401).send(); // Unauthorized
		return;
	})
	.catch(e => {
		console.log("Unauthorized access to ", token);
		res.status(401).send(); // Unauthorized
		return;
	});
}

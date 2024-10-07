import { Request, Response, NextFunction } from "express";

import { jwtVerify, SignJWT } from 'jose';
import { config } from "../../config";
import { getUser, UserEntity, UserId } from "../entities/user.entity";


type TokenPayloadVersion = 1;
const TOKEN_PAYLOAD_VERSION: TokenPayloadVersion = 1;

type AppTokenPayload = {
	// Increment TokenPayloadVersion whenever AppTokenPayload content changes to invalidate existing tokens
	v: TokenPayloadVersion;
	uuid: string;
}

export type AppTokenUser = {
	username: string;
	id: UserId;
	did: string;
}

export async function createAppToken(user: UserEntity): Promise<string> {
	const secret = new TextEncoder().encode(config.appSecret);
	const payload: AppTokenPayload = {
		v: TOKEN_PAYLOAD_VERSION,
		uuid: user.uuid.id,
	};
	return await new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256" })
		.sign(secret);
}

async function verifyApptoken(jwt: string): Promise<AppTokenPayload | false> {
	const secret = new TextEncoder().encode(config.appSecret);
	try {
		const { payload, protectedHeader } = await jwtVerify(jwt, secret);
		if (payload?.v === TOKEN_PAYLOAD_VERSION) {
			// The combination of a valid signature and the correct version
			// guarantees that this type assertion is sound
			return payload as AppTokenPayload;
		} else {
			console.log(`Incorrect token version: expected: ${TOKEN_PAYLOAD_VERSION}, got: ${payload?.v}`);
			return null;
		}
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

		const userId = UserId.fromId(payload.uuid);
		const userRes = await getUser(userId);
		if (userRes.ok) {
			req.user = {
				username: userRes.val.username,
				id: userId,
				did: userRes.val.did,
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

import { Request, Response, NextFunction } from "express";

import { jwtVerify } from 'jose';
import config from "../../config";
import { getUserByDID } from "../entities/user.entity";

export type AppTokenUser = {
	did: string;
}

function getCookieDictionary(cookies: any) {
  const cookieList = cookies.split('; ');
  let cookieDict: any = {};
  for (const cookie of cookieList) {
    const key = cookie.split('=')[0] as string;

    const val = cookie.split('=')[1];
    cookieDict[key] = val;
    
  }
  return cookieDict;
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
			did: (payload as AppTokenUser).did
		};
		const userRes = await getUserByDID(req.user.did);
		if (userRes.err) {
			res.status(401).send(); // Unauthorized
			return;
		}
		return next();
	})
	.catch(e => {
		console.log("Unauthorized access to ", token);
		res.status(401).send(); // Unauthorized
		return;
	});
}

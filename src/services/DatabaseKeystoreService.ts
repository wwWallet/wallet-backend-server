import { SignJWT, importJWK } from "jose";
import { AdditionalKeystoreParameters, WalletKeystore } from "./interfaces";
import { getUserByDID } from "../entities/user.entity";
import { SignVerifiablePresentationJWT, WalletKey } from "@gunet/ssi-sdk";
import { randomUUID } from "crypto";
import { verifiablePresentationSchemaURL } from "../util/util";
import { injectable } from "inversify";
import "reflect-metadata";


@injectable()
export class DatabaseKeystoreService implements WalletKeystore {

	public static readonly identifier = "DatabaseKeystoreService"


	constructor() { }
	
	async createIdToken(userDid: string, nonce: string, audience: string, additionalParameters: AdditionalKeystoreParameters): Promise<{ id_token: string; }> {

		const user = (await getUserByDID(userDid)).unwrap();

		const keys = JSON.parse(user.keys.toString()) as WalletKey;
		const privateKey = await importJWK(keys.privateKey, keys.alg);

		const jws = await new SignJWT({ nonce: nonce })
			.setProtectedHeader({
				alg: keys.alg,
				typ: "JWT",
				kid: keys.did + "#" + keys.did.split(":")[2],
			})
			.setSubject(user.did)
			.setIssuer(user.did)
			.setExpirationTime('1m')
			.setAudience(audience)
			.setIssuedAt()
			.sign(privateKey);

		return { id_token: jws };	
	}

	async signJwtPresentation(userDid: string, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters: AdditionalKeystoreParameters): Promise<{ vpjwt: string }> {
		const user = (await getUserByDID(userDid)).unwrap();
		const keys = JSON.parse(user.keys.toString()) as WalletKey;
		const privateKey = await importJWK(keys.privateKey, keys.alg);

		const jws = await new SignVerifiablePresentationJWT()
			.setProtectedHeader({
				alg: keys.alg,
				typ: "JWT",
				kid: keys.did + "#" + keys.did.split(":")[2],
			})
			.setVerifiableCredential(verifiableCredentials)
			.setContext(["https://www.w3.org/2018/credentials/v1"])
			.setType(["VerifiablePresentation"])
			.setAudience(audience)
			.setCredentialSchema(
				verifiablePresentationSchemaURL, 
				"FullJsonSchemaValidator2021")
			.setIssuer(user.did)
			.setSubject(user.did)
			.setHolder(user.did)
			.setJti(`urn:id:${randomUUID()}`)
			.setNonce(nonce)
			.setIssuedAt()
			.setExpirationTime('1m')
			.sign(privateKey);
		return { vpjwt: jws };
	}

	async generateOpenid4vciProof(userDid: string, audience: string, nonce: string, additionalParameters: AdditionalKeystoreParameters): Promise<{ proof_jwt: string }> {

		const user = (await getUserByDID(userDid)).unwrap();

		const keys = JSON.parse(user.keys.toString()) as WalletKey;
		const privateKey = await importJWK(keys.privateKey, keys.alg);
		const header = {
			alg: keys.alg,
			typ: "openid4vci-proof+jwt",
			kid: keys.did + "#" + keys.did.split(":")[2]
		};
		
		const jws = await new SignJWT({ nonce: nonce })
			.setProtectedHeader(header)
			.setIssuedAt()
			.setIssuer(user.did)
			.setAudience(audience)
			.setExpirationTime('1m')
			.sign(privateKey);
		return { proof_jwt: jws };

	}

}

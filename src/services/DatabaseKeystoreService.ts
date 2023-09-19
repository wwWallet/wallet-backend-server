import { SignJWT, importJWK } from "jose";
import { randomUUID } from "crypto";
import { inject, injectable } from "inversify";
import "reflect-metadata";
import { Err, Ok, Result } from "ts-results";

import { SignVerifiablePresentationJWT, WalletKey } from "@gunet/ssi-sdk";
import { AdditionalKeystoreParameters, DidKeyUtilityService, RegistrationParams, WalletKeystore, WalletKeystoreErr } from "./interfaces";
import { verifiablePresentationSchemaURL } from "../util/util";
import { getUserByDID } from "../entities/user.entity";
import { TYPES } from "./types";
import config from "../../config";


@injectable()
export class DatabaseKeystoreService implements WalletKeystore {

	private readonly algorithm = config.alg;

	constructor(
		@inject(TYPES.DidKeyUtilityService) private didKeyUtilityService: DidKeyUtilityService
	) { }


	async initializeWallet(registrationParams: RegistrationParams): Promise<Result<{ did: string; key?: WalletKey }, WalletKeystoreErr>> {
		try {
			const { did, key } = await this.didKeyUtilityService.generateKeyPair();
			return Ok({ did, key });
		}
		catch(e) {
			return Err(WalletKeystoreErr.FAILED_TO_GENERATE_KEYS);
		}
	}

	
	async createIdToken(userDid: string, nonce: string, audience: string, additionalParameters: AdditionalKeystoreParameters): Promise<Result<{ id_token: string; }, WalletKeystoreErr>> {
		const user = (await getUserByDID(userDid)).unwrap();
		const keys = JSON.parse(user.keys.toString()) as WalletKey;

		if (!keys.privateKey) {
			return Err(WalletKeystoreErr.KEYS_UNAVAILABLE);
		}

		const privateKey = await importJWK(keys.privateKey, keys.alg);
		const jws = await new SignJWT({ nonce: nonce })
			.setProtectedHeader({
				alg: this.algorithm,
				typ: "JWT",
				kid: keys.verificationMethod,
			})
			.setSubject(user.did)
			.setIssuer(user.did)
			.setExpirationTime('1m')
			.setAudience(audience)
			.setIssuedAt()
			.sign(privateKey);

		return Ok({ id_token: jws });
	}

	async signJwtPresentation(userDid: string, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters: AdditionalKeystoreParameters): Promise<Result<{ vpjwt: string }, WalletKeystoreErr>> {
		const user = (await getUserByDID(userDid)).unwrap();
		const keys = JSON.parse(user.keys.toString()) as WalletKey;
		if (!keys.privateKey) {
			return Err(WalletKeystoreErr.KEYS_UNAVAILABLE);
		}

		const privateKey = await importJWK(keys.privateKey, keys.alg);
		const jws = await new SignVerifiablePresentationJWT()
			.setProtectedHeader({
				alg: this.algorithm,
				typ: "JWT",
				kid: keys.verificationMethod,
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
		return Ok({ vpjwt: jws });
	}

	async generateOpenid4vciProof(userDid: string, audience: string, nonce: string, additionalParameters: AdditionalKeystoreParameters): Promise<Result<{ proof_jwt: string }, WalletKeystoreErr>> {
		const user = (await getUserByDID(userDid)).unwrap();
		const keys = JSON.parse(user.keys.toString()) as WalletKey;
		if (!keys.privateKey) {
			return Err(WalletKeystoreErr.KEYS_UNAVAILABLE);
		}

		const privateKey = await importJWK(keys.privateKey, keys.alg);
		const header = {
			alg: this.algorithm,
			typ: "openid4vci-proof+jwt",
			kid: keys.verificationMethod
		};

		const jws = await new SignJWT({ nonce: nonce })
			.setProtectedHeader(header)
			.setIssuedAt()
			.setIssuer(user.did)
			.setAudience(audience)
			// .setExpirationTime('1m')
			.sign(privateKey);
		return Ok({ proof_jwt: jws });
	}

}

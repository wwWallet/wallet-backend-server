import { inject, injectable } from "inversify";
import { AdditionalKeystoreParameters, DidKeyUtilityService, RegistrationParams, WalletKeystore, WalletKeystoreErr, WalletKeystoreManager } from "./interfaces";
import { Err, Ok, Result } from "ts-results";
import 'reflect-metadata';
import { TYPES } from "./types";
import { WalletType, getUserByDID } from "../entities/user.entity";
import { WalletKey } from "@wwWallet/ssi-sdk";

/**
 * This class is responsible for deciding which WalletKeystore will be used each time depending on the user
 */
@injectable()
export class WalletKeystoreManagerService implements WalletKeystoreManager {

	constructor(
		@inject(TYPES.ClientKeystoreService) private clientWalletKeystoreService: WalletKeystore,
		@inject(TYPES.DatabaseKeystoreService) private databaseKeystoreService: WalletKeystore,
		@inject(TYPES.DidKeyUtilityService) private didKeyUtilityService: DidKeyUtilityService
	) { }

	async initializeWallet(registrationParams: RegistrationParams): Promise<Result<{ fcmToken: Buffer, browserFcmToken: Buffer, keys: Buffer, did: string, displayName: string, privateData: Buffer, walletType: WalletType }, WalletKeystoreErr>> {
		const fcmToken = registrationParams.fcm_token ? Buffer.from(registrationParams.fcm_token) : Buffer.from("");
		const browserFcmToken = registrationParams.browser_fcm_token ? Buffer.from(registrationParams.browser_fcm_token) : Buffer.from("");

		// depending on additionalParameters, decide to use the corresponding keystore service
		if (registrationParams.keys && registrationParams.privateData) {
			return Ok({
				fcmToken,
				browserFcmToken,
				keys: Buffer.from(JSON.stringify(registrationParams.keys)),
				did: registrationParams.keys.did,
				displayName: registrationParams.displayName,
				privateData: Buffer.from(registrationParams.privateData),
				walletType: WalletType.CLIENT
			});
		}
		else {
			try {
				console.log("Regular database")
				const { did, key } = await this.didKeyUtilityService.generateKeyPair();
				return Ok({
					fcmToken,
					browserFcmToken,
					keys: Buffer.from(JSON.stringify(key)),
					did: did,
					displayName: registrationParams.displayName,
					privateData: Buffer.from(""),
					walletType: WalletType.DB
				});
			}
			catch(e) {
				return Err(WalletKeystoreErr.FAILED_TO_GENERATE_KEYS);
			}
		}
	}
	
	async createIdToken(userDid: string, nonce: string, audience: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ id_token: string; }, WalletKeystoreErr>> {
		const userRes = await getUserByDID(userDid)
		if (userRes.err) {
			return Err(WalletKeystoreErr.KEYS_UNAVAILABLE);
		}
		const user = userRes.unwrap();
		if (user.walletType != WalletType.DB)
			return await this.clientWalletKeystoreService.createIdToken(userDid, nonce, audience, additionalParameters);
		else
			return await this.databaseKeystoreService.createIdToken(userDid, nonce, audience, additionalParameters);
	}

	async signJwtPresentation(userDid: string, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ vpjwt: string; }, WalletKeystoreErr>> {
		const userRes = await getUserByDID(userDid)
		if (userRes.err) {
			return Err(WalletKeystoreErr.KEYS_UNAVAILABLE);
		}
		const user = userRes.unwrap();
		if (user.walletType != WalletType.DB)
			return await this.clientWalletKeystoreService.signJwtPresentation(userDid, nonce, audience, verifiableCredentials, additionalParameters);
		else
			return await this.databaseKeystoreService.signJwtPresentation(userDid, nonce, audience, verifiableCredentials, additionalParameters);
	}

	async generateOpenid4vciProof(userDid: string, audience: string, nonce: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ proof_jwt: string; }, WalletKeystoreErr>> {
		const userRes = await getUserByDID(userDid)
		if (userRes.err) {
			return Err(WalletKeystoreErr.KEYS_UNAVAILABLE);
		}
		const user = userRes.unwrap();
		if (user.walletType != WalletType.DB)
			return await this.clientWalletKeystoreService.generateOpenid4vciProof(userDid, audience, nonce, additionalParameters);
		else
			return await this.databaseKeystoreService.generateOpenid4vciProof(userDid, audience, nonce, additionalParameters);
	}

}
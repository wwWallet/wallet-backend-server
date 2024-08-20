import { inject, injectable } from "inversify";
import { AdditionalKeystoreParameters, DidKeyUtilityService, RegistrationParams, WalletKeystore, WalletKeystoreErr, WalletKeystoreManager } from "./interfaces";
import { Err, Ok, Result } from "ts-results";
import 'reflect-metadata';
import { TYPES } from "./types";
import { UserId, WalletType, getUser } from "../entities/user.entity";

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

	async initializeWallet(registrationParams: RegistrationParams): Promise<Result<{ fcmToken: string, keys: Buffer, displayName: string, privateData: Buffer, walletType: WalletType }, WalletKeystoreErr>> {
		const fcmToken = registrationParams.fcm_token ? registrationParams.fcm_token : "";

		// depending on additionalParameters, decide to use the corresponding keystore service
		if (registrationParams.privateData) {
			return Ok({
				fcmToken,
				keys: Buffer.from(""),
				displayName: registrationParams.displayName,
				privateData: Buffer.from(registrationParams.privateData),
				walletType: WalletType.CLIENT
			});
		}
		else {
			try {
				console.log("Regular database")
				const { key } = await this.didKeyUtilityService.generateKeyPair();
				return Ok({
					fcmToken,
					keys: Buffer.from(JSON.stringify(key)),
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

	async signJwtPresentation(userId: UserId, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ vpjwt: string; }, WalletKeystoreErr>> {
		const userRes = await getUser(userId)
		if (userRes.err) {
			return Err(WalletKeystoreErr.KEYS_UNAVAILABLE);
		}
		const user = userRes.unwrap();
		if (user.walletType != WalletType.DB)
			return await this.clientWalletKeystoreService.signJwtPresentation(userId, nonce, audience, verifiableCredentials, additionalParameters);
		else
			return await this.databaseKeystoreService.signJwtPresentation(userId, nonce, audience, verifiableCredentials, additionalParameters);
	}

	async generateOpenid4vciProof(userId: UserId, audience: string, nonce: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ proof_jwt: string; }, WalletKeystoreErr>> {
		const userRes = await getUser(userId)
		if (userRes.err) {
			return Err(WalletKeystoreErr.KEYS_UNAVAILABLE);
		}
		const user = userRes.unwrap();
		if (user.walletType != WalletType.DB)
			return await this.clientWalletKeystoreService.generateOpenid4vciProof(userId, audience, nonce, additionalParameters);
		else
			return await this.databaseKeystoreService.generateOpenid4vciProof(userId, audience, nonce, additionalParameters);
	}

}

import { inject, injectable } from "inversify";
import { AdditionalKeystoreParameters, RegistrationParams, WalletKeystore, WalletKeystoreErr, WalletKeystoreManager } from "./interfaces";
import { Ok, Result } from "ts-results";
import 'reflect-metadata';
import { TYPES } from "./types";
import { UserId, WalletType } from "../entities/user.entity";

/**
 * This class is responsible for deciding which WalletKeystore will be used each time depending on the user
 */
@injectable()
export class WalletKeystoreManagerService implements WalletKeystoreManager {

	constructor(
		@inject(TYPES.ClientKeystoreService) private clientWalletKeystoreService: WalletKeystore,
	) { }

	async initializeWallet(registrationParams: RegistrationParams): Promise<Result<{ fcmToken: string, keys: Buffer, displayName: string, privateData: Buffer, walletType: WalletType }, WalletKeystoreErr>> {
		const fcmToken = registrationParams.fcm_token ? registrationParams.fcm_token : "";
		return Ok({
			fcmToken,
			keys: Buffer.from(""),
			displayName: registrationParams.displayName,
			privateData: Buffer.from(registrationParams.privateData),
			walletType: WalletType.CLIENT
		});
	}

	async signJwtPresentation(userId: UserId, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ vpjwt: string; }, WalletKeystoreErr>> {
		return await this.clientWalletKeystoreService.signJwtPresentation(userId, nonce, audience, verifiableCredentials, additionalParameters);
	}

	async generateOpenid4vciProof(userId: UserId, audience: string, nonce: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ proof_jwt: string; }, WalletKeystoreErr>> {
		return await this.clientWalletKeystoreService.generateOpenid4vciProof(userId, audience, nonce, additionalParameters);
	}

}

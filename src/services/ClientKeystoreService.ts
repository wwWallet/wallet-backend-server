import { randomUUID } from "crypto";
import { inject, injectable } from "inversify";
import "reflect-metadata";
import { Err, Ok, Result } from "ts-results";

import { AdditionalKeystoreParameters, RegistrationParams, SocketManagerServiceInterface, WalletKeystore, WalletKeystoreErr } from "./interfaces";
import { TYPES } from "./types";
import config from "../../config";
import { SignatureAction, ServerSocketMessage } from "./shared.types";
import { WalletKey } from "@wwwallet/ssi-sdk";



@injectable()
export class ClientKeystoreService implements WalletKeystore {

	private readonly algorithm = config.alg;



	constructor(
		@inject(TYPES.SocketManagerService) private socketManagerService: SocketManagerServiceInterface,
	) { }


	async createIdToken(userDid: string, nonce: string, audience: string, additionalParameters: AdditionalKeystoreParameters): Promise<Result<{ id_token: string; }, WalletKeystoreErr>> {
		let message_id_sent = randomUUID();
		const msg = {
			message_id: message_id_sent,
			request: {
				action: SignatureAction.createIdToken,
				nonce: nonce,
				audience: audience
			}
		}
		await this.socketManagerService.send(userDid, msg as ServerSocketMessage)

		const result = await this.socketManagerService.expect(userDid, message_id_sent, SignatureAction.createIdToken);
		if (result.err) {
			return Err(WalletKeystoreErr.REMOTE_SIGNING_FAILED);
		}
		const { message: { message_id, response } } = result.unwrap();
		if (response.action == SignatureAction.createIdToken) {
			return Ok({ id_token: response.id_token });
		}
		return Err(WalletKeystoreErr.REMOTE_SIGNING_FAILED);
	}

	async signJwtPresentation(userDid: string, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters: AdditionalKeystoreParameters): Promise<Result<{ vpjwt: string }, WalletKeystoreErr>> {
		let message_id_sent = randomUUID();
		const msg = {
			message_id: message_id_sent,
			request: {
				action: SignatureAction.signJwtPresentation,
				nonce: nonce,
				audience: audience,
				verifiableCredentials: verifiableCredentials
			}
		}
		await this.socketManagerService.send(userDid, msg as ServerSocketMessage)

		const result = await this.socketManagerService.expect(userDid, message_id_sent, SignatureAction.signJwtPresentation);
		if (result.err) {
			return Err(WalletKeystoreErr.REMOTE_SIGNING_FAILED);
		}
		const { message: { message_id, response } } = result.unwrap();
		if (response.action == SignatureAction.signJwtPresentation) {
			return Ok({ vpjwt: response.vpjwt });
		}
		return Err(WalletKeystoreErr.REMOTE_SIGNING_FAILED);
	}

	async generateOpenid4vciProof(userDid: string, audience: string, nonce: string, additionalParameters: AdditionalKeystoreParameters): Promise<Result<{ proof_jwt: string }, WalletKeystoreErr>> {
		let message_id_sent = randomUUID();
		const msg = {
			message_id: message_id_sent,
			request: {
				action: SignatureAction.generateOpenid4vciProof,
				nonce: nonce,
				audience: audience
			}
		}
		console.log("MessageID = ", message_id_sent)
		await this.socketManagerService.send(userDid, msg as ServerSocketMessage);
		const result = await this.socketManagerService.expect(userDid, message_id_sent, SignatureAction.generateOpenid4vciProof);
		if (result.err) {
			return Err(WalletKeystoreErr.REMOTE_SIGNING_FAILED);
		}
		const { message: { message_id, response } } = result.unwrap();
		if (response.action == SignatureAction.generateOpenid4vciProof) {
			return Ok({ proof_jwt: response.proof_jwt });
		}
		return Err(WalletKeystoreErr.REMOTE_SIGNING_FAILED);
	}

}

import { JWK } from "jose";
import { Result } from "ts-results";
import { LegalPersonEntity } from "../entities/LegalPerson.entity";
import { OutboundRequest } from "./types/OutboundRequest";
import http from 'http';
import { WalletKeystoreRequest, ServerSocketMessage, SignatureAction, ClientSocketMessage } from "./shared.types";
import { WalletKey } from "@wwwallet/ssi-sdk";
import { WalletType } from "../entities/user.entity";

export interface OpenidCredentialReceiving {

	getAvailableSupportedCredentials(userDid: string, legalPersonIdentifier: string): Promise<Array<{id: string, displayName: string}>>
	generateAuthorizationRequestURL(userDid: string, credentialOfferURL?: string, legalPersonIdentifier?: string): Promise<{ redirect_to?: string, preauth?: boolean, ask_for_pin?: boolean }>;

	handleAuthorizationResponse(userDid: string, authorizationResponseURL: string): Promise<Result<void, IssuanceErr | WalletKeystoreRequest>>;
	requestCredentialsWithPreAuthorizedGrant(userDid: string, user_pin: string): Promise<{error?: string}>;

	getIssuerState(userDid: string): Promise<{ issuer_state?: string, error?: Error }>
}

export enum IssuanceErr {
	STATE_NOT_FOUND = "STATE_NOT_FOUND",
}

export enum HandleOutboundRequestError {
	INSUFFICIENT_CREDENTIALS = "INSUFFICIENT_CREDENTIALS",
}

export enum SendResponseError {
	SEND_RESPONSE_ERROR = "SEND_RESPONSE_ERROR",
}


export type AdditionalKeystoreParameters = {

}

export type RegistrationParams = {
	fcm_token?: string;
	keys?: WalletKey;
	privateData?: Buffer;
	displayName: string;
}


export interface WalletKeystoreManager {
	initializeWallet(registrationParams: RegistrationParams): Promise<Result<{ fcmToken: string, keys: Buffer, did: string, displayName: string, privateData: Buffer, walletType: WalletType }, WalletKeystoreErr>>;

	createIdToken(userDid: string, nonce: string, audience: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ id_token: string }, WalletKeystoreErr>>;
	signJwtPresentation(userDid: string, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ vpjwt: string }, WalletKeystoreErr>>;
	generateOpenid4vciProof(userDid: string, audience: string, nonce: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ proof_jwt: string }, WalletKeystoreErr>>;
}

export interface WalletKeystore {

	createIdToken(userDid: string, nonce: string, audience: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ id_token: string }, WalletKeystoreErr>>;
	signJwtPresentation(userDid: string, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ vpjwt: string }, WalletKeystoreErr>>;
	generateOpenid4vciProof(userDid: string, audience: string, nonce: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ proof_jwt: string }, WalletKeystoreErr>>;
}

export enum WalletKeystoreErr {
	ADDITIONAL_PARAMS_NOT_FOUND = "additional-params-not-found",
	FAILED_TO_GENERATE_KEYS = "keys-failed-to-generate",
	KEYS_UNAVAILABLE = "keys-unavailable",
	REMOTE_SIGNING_FAILED = "remote-signing-failed"
}



export interface OutboundCommunication {
	initiateVerificationFlow(username: string, verifierId: number, scopeName: string): Promise<{ redirect_to?: string }>;

	handleRequest(userDid: string, requestURL: string, camera_was_used: boolean): Promise<Result<OutboundRequest, WalletKeystoreRequest | HandleOutboundRequestError>>;

	/**
	 *
	 * @param userDid
	 * @param req
	 * @param selection (key: descriptor_id, value: verifiable credential identifier)
	 */
	sendResponse(userDid: string, selection: Map<string, string>): Promise<Result<{ redirect_to?: string }, WalletKeystoreRequest | SendResponseError>>;
}


export interface LegalPersonsRegistry {
	getByIdentifier(did: string): Promise<LegalPersonEntity>;
}

export interface DidKeyUtilityService {
	getPublicKeyJwk(did: string): Promise<JWK>;
	generateKeyPair(): Promise<{ did: string, key: WalletKey }>
}




export enum ExpectingSocketMessageErr {
	WRONG_MESSAGE_ID = 'wrong-message-id',
	WRONG_ACTION = 'wrong-action',
	FAILED_TO_RECEIVE = 'failed-to-receive'
}

export interface SocketManagerServiceInterface {
	register(server: http.Server);

	send(userDid: string, message: ServerSocketMessage): Promise<Result<void, void>>;
	expect(userDid: string, message_id: string, action: SignatureAction): Promise<Result<{ message: ClientSocketMessage }, ExpectingSocketMessageErr>>;
}

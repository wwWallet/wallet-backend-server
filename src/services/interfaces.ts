import { JWK } from "jose";
import { Result } from "ts-results";
import { LegalPersonEntity } from "../entities/LegalPerson.entity";
import { OutboundRequest } from "./types/OutboundRequest";
import http from 'http';
import { WalletKeystoreRequest, ServerSocketMessage, SignatureAction, ClientSocketMessage } from "./shared.types";
import { WalletKey } from "@wwwallet/ssi-sdk";
import { UserId, WalletType } from "../entities/user.entity";

export interface OpenidCredentialReceiving {

	generateAuthorizationRequestURL(userId: UserId, credentialOfferURL?: string, legalPersonIdentifier?: string): Promise<{ redirect_to?: string, preauth?: boolean, ask_for_pin?: boolean }>;

	handleAuthorizationResponse(userId: UserId, authorizationResponseURL: string): Promise<Result<void, IssuanceErr | WalletKeystoreRequest>>;
	requestCredentialsWithPreAuthorizedGrant(userId: UserId, user_pin: string): Promise<{error?: string}>;

	getIssuerState(userId: UserId): Promise<{ issuer_state?: string, error?: Error }>
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
	initializeWallet(registrationParams: RegistrationParams): Promise<Result<{ fcmToken: string, keys: Buffer, displayName: string, privateData: Buffer, walletType: WalletType }, WalletKeystoreErr>>;

	createIdToken(userId: UserId, nonce: string, audience: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ id_token: string }, WalletKeystoreErr>>;
	signJwtPresentation(userId: UserId, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ vpjwt: string }, WalletKeystoreErr>>;
	generateOpenid4vciProof(userId: UserId, audience: string, nonce: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ proof_jwt: string }, WalletKeystoreErr>>;
}

export interface WalletKeystore {

	createIdToken(userId: UserId, nonce: string, audience: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ id_token: string }, WalletKeystoreErr>>;
	signJwtPresentation(userId: UserId, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ vpjwt: string }, WalletKeystoreErr>>;
	generateOpenid4vciProof(userId: UserId, audience: string, nonce: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ proof_jwt: string }, WalletKeystoreErr>>;
}

export enum WalletKeystoreErr {
	ADDITIONAL_PARAMS_NOT_FOUND = "additional-params-not-found",
	FAILED_TO_GENERATE_KEYS = "keys-failed-to-generate",
	KEYS_UNAVAILABLE = "keys-unavailable",
	REMOTE_SIGNING_FAILED = "remote-signing-failed"
}



export interface OutboundCommunication {
	initiateVerificationFlow(userId: UserId, verifierId: number, scopeName: string): Promise<{ redirect_to?: string }>;
	handleRequest(userId: UserId, requestURL: string, camera_was_used: boolean): Promise<Result<OutboundRequest, WalletKeystoreRequest | HandleOutboundRequestError>>;
	sendResponse(userId: UserId, selection: Map<string, string>): Promise<Result<{ redirect_to?: string }, WalletKeystoreRequest | SendResponseError>>;
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

	send(userId: UserId, message: ServerSocketMessage): Promise<Result<void, void>>;
	expect(userId: UserId, message_id: string, action: SignatureAction): Promise<Result<{ message: ClientSocketMessage }, ExpectingSocketMessageErr>>;
}

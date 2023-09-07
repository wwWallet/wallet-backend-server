import { Result } from "ts-results";
import { LegalPersonEntity } from "../entities/LegalPerson.entity";
import { OutboundRequest } from "./types/OutboundRequest";

export interface OpenidCredentialReceiving {
	
	getAvailableSupportedCredentials(userDid: string, legalPersonIdentifier: string): Promise<Array<{id: string, displayName: string}>>
	generateAuthorizationRequestURL(userDid: string, credentialOfferURL?: string, legalPersonIdentifier?: string): Promise<{ redirect_to: string }>
	
	handleAuthorizationResponse(userDid: string, authorizationResponseURL: string): Promise<Result<void, IssuanceErr | void>>;
	requestCredentialsWithPreAuthorizedGrant(userDid: string, user_pin: string): Promise<void>;

	getIssuerState(userDid: string): Promise<{ issuer_state?: string, error?: Error }>
}

export enum IssuanceErr {
	STATE_NOT_FOUND = "STATE_NOT_FOUND",
}


export type AdditionalKeystoreParameters = {
	
}


export interface WalletKeystore {
	createIdToken(userDid: string, nonce: string, audience: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ id_token: string }, WalletKeystoreErr>>;
	signJwtPresentation(userDid: string, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ vpjwt: string }, WalletKeystoreErr>>;
	generateOpenid4vciProof(userDid: string, audience: string, nonce: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ proof_jwt: string }, WalletKeystoreErr>>;
}

export enum WalletKeystoreErr {
	KEYS_UNAVAILABLE = "keys-unavailable",
}


export interface OutboundCommunication {
	
	handleRequest(userDid: string, requestURL: string): Promise<Result<OutboundRequest, void>>;

	/**
	 * 
	 * @param userDid
	 * @param req 
	 * @param selection (key: descriptor_id, value: verifiable credential identifier)
	 */
	sendResponse(userDid: string, selection: Map<string, string>): Promise<Result<{ redirect_to?: string, error?: Error }, void>>;
}


export interface LegalPersonsRegistry {
	getByIdentifier(did: string): Promise<LegalPersonEntity>;
}

import { JWK } from "jose";
import { LegalPersonEntity } from "../entities/LegalPerson.entity";
import { OutboundRequest } from "./types/OutboundRequest";

export interface OpenidCredentialReceiving {
	
	getAvailableSupportedCredentials(username: string, legalPersonIdentifier: string): Promise<Array<{id: string, displayName: string}>>
	generateAuthorizationRequestURL(username: string, credentialOfferURL?: string, legalPersonIdentifier?: string): Promise<{ redirect_to: string }> 
	
	handleAuthorizationResponse(username: string, authorizationResponseURL: string): Promise<void>;
	requestCredentialsWithPreAuthorizedGrant(username: string, user_pin: string): Promise<void>;

	getIssuerState(username: string): Promise<{ issuer_state?: string, error?: Error }>
}


export type AdditionalKeystoreParameters = {
	
}


export interface WalletKeystore {
	generateKeyPair(username: string): Promise<{ did: string }>;
	createIdToken(username: string, nonce: string, audience: string, additionalParameters?: AdditionalKeystoreParameters): Promise<{id_token: string}>;
	signJwtPresentation(username: string, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters?: AdditionalKeystoreParameters): Promise<{ vpjwt: string }>;
	generateOpenid4vciProof(username: string, audience: string, nonce: string, additionalParameters?: AdditionalKeystoreParameters): Promise<{ proof_jwt: string }>;
	getIdentifier(username: string): Promise<string>; // later can be converted into getIdentifiers() for more than one
}



export interface OutboundCommunication {
	

	initiateVerificationFlow(username: string, verifierId: number, scopeName: string): Promise<{ redirect_to?: string }>;

	handleRequest(username: string, requestURL: string): Promise<OutboundRequest>;

	/**
	 * 
	 * @param username 
	 * @param req 
	 * @param selection (key: descriptor_id, value: verifiable credential identifier)
	 */
	sendResponse(username: string, selection: Map<string, string>): Promise<{ redirect_to?: string, error?: Error }>;
}


export interface LegalPersonsRegistry {
	getByIdentifier(did: string): Promise<LegalPersonEntity>;
}

export interface DidKeyUtilityService {
	getPublicKeyJwk(did: string): Promise<JWK>;
	generateKeyPair(): Promise<{ did: string, key: any }>
}
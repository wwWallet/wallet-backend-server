import { LegalPersonEntity } from "../entities/LegalPerson.entity";
import { OutboundRequest } from "./types/OutboundRequest";

export interface OpenidCredentialReceiving {
	
	getAvailableSupportedCredentials(userDid: string, legalPersonIdentifier: string): Promise<Array<{id: string, displayName: string}>>
	generateAuthorizationRequestURL(userDid: string, credentialOfferURL?: string, legalPersonIdentifier?: string): Promise<{ redirect_to: string }>
	
	handleAuthorizationResponse(userDid: string, authorizationResponseURL: string): Promise<void>;
	requestCredentialsWithPreAuthorizedGrant(userDid: string, user_pin: string): Promise<void>;

	getIssuerState(userDid: string): Promise<{ issuer_state?: string, error?: Error }>
}


export type AdditionalKeystoreParameters = {
	
}


export interface WalletKeystore {
	createIdToken(userDid: string, nonce: string, audience: string, additionalParameters?: AdditionalKeystoreParameters): Promise<{id_token: string}>;
	signJwtPresentation(userDid: string, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters?: AdditionalKeystoreParameters): Promise<{ vpjwt: string }>;
	generateOpenid4vciProof(userDid: string, audience: string, nonce: string, additionalParameters?: AdditionalKeystoreParameters): Promise<{ proof_jwt: string }>;
}



export interface OutboundCommunication {
	
	handleRequest(userDid: string, requestURL: string): Promise<OutboundRequest>;

	/**
	 * 
	 * @param userDid
	 * @param req 
	 * @param selection (key: descriptor_id, value: verifiable credential identifier)
	 */
	sendResponse(userDid: string, selection: Map<string, string>): Promise<{ redirect_to?: string, error?: Error }>;
}


export interface LegalPersonsRegistry {
	getByIdentifier(did: string): Promise<LegalPersonEntity>;
}

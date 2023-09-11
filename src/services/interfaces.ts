import { JWK } from "jose";
import { Result } from "ts-results";
import { LegalPersonEntity } from "../entities/LegalPerson.entity";
import { OutboundRequest } from "./types/OutboundRequest";

export interface OpenidCredentialReceiving {
	
	getAvailableSupportedCredentials(userDid: string, legalPersonIdentifier: string): Promise<Array<{id: string, displayName: string}>>
	generateAuthorizationRequestURL(userDid: string, credentialOfferURL?: string, legalPersonIdentifier?: string): Promise<{ redirect_to: string }>
	
	handleAuthorizationResponse(userDid: string, authorizationResponseURL: string, proof_jwt: string | null): Promise<Result<void, IssuanceErr | WalletKeystoreRequest>>;
	requestCredentialsWithPreAuthorizedGrant(userDid: string, user_pin: string): Promise<void>;

	getIssuerState(userDid: string): Promise<{ issuer_state?: string, error?: Error }>
}

export enum IssuanceErr {
	STATE_NOT_FOUND = "STATE_NOT_FOUND",
}


export type AdditionalKeystoreParameters = {
	
}


export interface WalletKeystore {
	// generateKeyPair(username: string): Promise<{ did: string }>;
	// getIdentifier(username: string): Promise<string>; // later can be converted into getIdentifiers() for more than one

	createIdToken(userDid: string, nonce: string, audience: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ id_token: string }, WalletKeystoreErr>>;
	signJwtPresentation(userDid: string, nonce: string, audience: string, verifiableCredentials: any[], additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ vpjwt: string }, WalletKeystoreErr>>;
	generateOpenid4vciProof(userDid: string, audience: string, nonce: string, additionalParameters?: AdditionalKeystoreParameters): Promise<Result<{ proof_jwt: string }, WalletKeystoreErr>>;
}

export enum WalletKeystoreErr {
	KEYS_UNAVAILABLE = "keys-unavailable",
}

export type WalletKeystoreRequest = (
	{ action: "generateOpenid4vciProof", audience: string, nonce: string }
	| { action: "createIdToken", nonce: string, audience: string }
	| { action: "signJwtPresentation", nonce: string, audience: string, verifiableCredentials: any[] }
);


export interface OutboundCommunication {
	initiateVerificationFlow(username: string, verifierId: number, scopeName: string): Promise<{ redirect_to?: string }>;

	handleRequest(userDid: string, requestURL: string, id_token: string | null): Promise<Result<OutboundRequest, WalletKeystoreRequest>>;

	/**
	 * 
	 * @param userDid
	 * @param req 
	 * @param selection (key: descriptor_id, value: verifiable credential identifier)
	 */
	sendResponse(userDid: string, selection: Map<string, string>, vpjwt: string | null): Promise<Result<{ redirect_to?: string, error?: Error }, WalletKeystoreRequest>>;
}


export interface LegalPersonsRegistry {
	getByIdentifier(did: string): Promise<LegalPersonEntity>;
}

export interface DidKeyUtilityService {
	getPublicKeyJwk(did: string): Promise<JWK>;
	generateKeyPair(): Promise<{ did: string, key: any }>
}

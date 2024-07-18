import { JWK } from 'jose';

export type AuthorizationDetail = {
	type: string,
	format: VerifiableCredentialFormat,
	types: string[],
	locations?: string[]
}

export type AuthorizationDetails = AuthorizationDetail[];

export type OpenidConfiguration = {
	authorization_endpoint: string;
	token_endpoint: string;
}

export enum GrantType {
	AUTHORIZATION_CODE = "authorization_code",
	PRE_AUTHORIZED_CODE = "pre-authorized_code"
}


export type CredentialOffer = {
	credential_issuer: string,
	credentials: CredentialOfferCredential[],
	grants: {
		"authorization_code"?: {
			"issuer_state"?: string
		},
		"urn:ietf:params:oauth:grant-type:pre-authorized_code"?: {
			"pre-authorized_code": string,
      "user_pin_required": boolean
		}
	}
}



export type CredentialOfferCredential = {
	format: VerifiableCredentialFormat,
	types: string[] // VerifiableCredential, UniversityDegreeCredential
}

export type CredentialIssuerMetadata = {
	credential_issuer: string,
	authorization_server: string,
	credential_endpoint: string,
	batch_credential_endpoint?: string,
	deferred_credential_endpoint?: string,
	credentials_supported: CredentialSupported[],
	display?: Display[]
}

export type Display = {
	name: string,
	locale?: string,
	logo?: {
		url?: string,
		alt_text?: string
	},
	description?: string,
	background_color?: string,
	text_color?: string
	background_image_url?: string // added by us
}


export type CredentialSupported = CredentialSupportedJwtVcJson; // | CredentialSupportedJsonLd ...

export type CredentialSupportedBase = {
	id?: string,
	format: VerifiableCredentialFormat,
	cryptographic_binding_methods_supported?: string[],
	cryptographic_suites_supported?: string[],
	display?: Display[]
}

// additional attributes for credentials_supported object for the 'jwt_vc_json' format specifically
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-objects-comprising-credenti
// extended by:
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-vc-signed-as-a-jwt-not-usin
export type CredentialSupportedJwtVcJson = CredentialSupportedBase & {
	types?: string[], // required if jwt vc json
	credentialSubject?: {
		mandatory: boolean,
		value_type?: string
	},
	order?: string[]
}

export type JwtProof = {
	proof_type?: string;
	jwt?: string;
}


export type ProofHeader = {
	alg: string;

	/**
	 * CONDITIONAL. JWT header containing the key ID.
	 * If the credential shall be bound to a DID, the kid refers to a DID URL which identifies a particular key in the DID Document that the credential shall be bound to.
	 */
	kid?: string;

	/**
	 * CONDITIONAL. JWT header containing the key material the new credential shall be bound to. MUST NOT be present if kid is present.
	 * REQUIRED for EBSI DID Method for Natural Persons.
	 */
	jwk?: JWK;
}

export type ProofPayload = {
	/**
	 * REQUIRED. MUST contain the client_id of the sender.
	 * in DID format
	 */
	iss: string;

	/**
	 * REQUIRED. MUST contain the issuer URL of the credential issuer.
	 */
	aud: string;

	iat: number;


	/**
	 * REQUIRED. MUST be Token Response c_nonce as provided by the issuer.
	 */
	nonce: string;
}


export enum VerifiableCredentialFormat {
	JWT_VC_JSON = "jwt_vc_json",
	JWT_VC = "jwt_vc",
	LDP_VC = "ldp_vc",
	VC_SD_JWT = "vc+sd-jwt"
}

export enum ProofType {
	JWT = "jwt"
}

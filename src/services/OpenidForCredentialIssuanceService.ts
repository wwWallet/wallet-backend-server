import axios from "axios";
import * as _ from 'lodash';
import base64url from "base64url";
import qs from "qs";
import { injectable, inject } from "inversify";
import "reflect-metadata";
import { Err, Ok, Result } from "ts-results";

import { LegalPersonEntity, getLegalPersonByDID, getLegalPersonByUrl } from "../entities/LegalPerson.entity";
import { CredentialIssuerMetadata, CredentialResponseSchemaType, CredentialSupportedJwtVcJson, GrantType, OpenidConfiguration, TokenResponseSchemaType, VerifiableCredentialFormat } from "../types/oid4vci";
import config from "../../config";
import { getUserByDID } from "../entities/user.entity";
import { sendPushNotification } from "../lib/firebase";
import { generateCodeChallengeFromVerifier, generateCodeVerifier } from "../util/util";
import { createVerifiableCredential } from "../entities/VerifiableCredential.entity";
import { getLeafNodesWithPath } from "../lib/leafnodepaths";
import { TYPES } from "./types";
import { IssuanceErr, OpenidCredentialReceiving, WalletKeystore, WalletKeystoreErr } from "./interfaces";


type IssuanceState = {
	userDid: string;  // Before Authorization Req
	legalPerson: LegalPersonEntity; // Before Authorization Req
	credentialIssuerMetadata: CredentialIssuerMetadata; // Before Authorization Req
	openidConfiguration: OpenidConfiguration; // Before Authorization Req
	issuer_state?: string; // parameter from the authorization request
	authorization_details: CredentialSupportedJwtVcJson[]; // This is defined before the Authorization Req, and after the Token Response (if available)
	code_verifier?: string;
	code?: string; // set at Authorization Response
	grant_type: GrantType,
	tokenResponse?: TokenResponseSchemaType; // set at Token Response
	credentialResponses?: CredentialResponseSchemaType[];  // set at Credential Response
	user_pin?: string; // for pre-authorize flow only
}

@injectable()
export class OpenidForCredentialIssuanceService implements OpenidCredentialReceiving {

	public static readonly identifier = "OpenidForCredentialIssuanceService"
	// identifierService: IdentifierService = new IdentifierService();
	// legalPersonService: LegalPersonService = new LegalPersonService();
	

	// key: userDid
	public states = new Map<string, IssuanceState>();


	// This is a queue of the credentials which are ready
	// to be received.
	// When a credential is ready to be received, the credential response
	// is added for specific fcm token and a notification is sent to the device.
	// key: userDid, value: array of credential responses
	credentialQueue = new Map<string, CredentialResponseSchemaType[]>();

	constructor(
		@inject(TYPES.WalletKeystore) private walletKeyStore: WalletKeystore,
	) { }


	async getIssuerState(userDid: string): Promise<{ issuer_state?: string, error?: Error; }> {
		const state = this.states.get(userDid);
		if (!state) {
			return { issuer_state: null, error: new Error("No state found") };
		}
		if (!state.issuer_state) {
			return { issuer_state: null, error: new Error("No issuer_state found in state") };
		}
		
		return { issuer_state: state.issuer_state, error: null };
	}

	async getAvailableSupportedCredentials(legalPersonDID: string): Promise<Array<{id: string, displayName: string}>> {
		const lp = (await getLegalPersonByDID(legalPersonDID)).unwrapOr(new Error("Not found"));
		if (lp instanceof Error) {
			return [];
		}
		const issuerUrlString = lp.url;
		const credentialIssuerMetadata = await axios.get(issuerUrlString + "/.well-known/openid-credential-issuer");

		const options = credentialIssuerMetadata.data.credentials_supported.map((val) => {
			return { id: val.id, displayName: val.display[0].name };
		})
		return options as Array<{id: string, displayName: string}>;
	}

	/**
	 * 
	 * @param userDid
	 * @param legalPersonDID 
	 * @returns 
	 * @throws
	 */
	async generateAuthorizationRequestURL(userDid: string, credentialOfferURL?: string, legalPersonDID?: string): Promise<{ redirect_to: string }> {
		console.log("generateAuthorizationRequestURL userDid = ", userDid);
		console.log("LP = ", legalPersonDID);
		let issuerUrlString: string | null = null;
		let credential_offer = null;
		let issuer_state = null;
		const client_metadata = {
			jwks_uri: config.url + "/jwks",
			vp_formats_supported: {
				jwt_vp: {
					alg: ["ES256"]
				}
			},
			response_types_supported: [ "vp_token", "id_token" ]
		};

		let lp: LegalPersonEntity;

		if (legalPersonDID) {
			lp = (await getLegalPersonByDID(legalPersonDID)).unwrap();
			if (!lp) {
				throw "No legal person found in the DB"
			}
			console.log("Selected legal person = ", lp)
			issuerUrlString = lp.url;
		}
		else if (credentialOfferURL) {
			console.log("Credential offer url = ", credentialOfferURL)

			credential_offer = qs.parse(credentialOfferURL.split('?')[1]) as any;
			if (credential_offer.credential_offer_uri && typeof credential_offer.credential_offer_uri == 'string') {
				credential_offer = (await axios.get(credential_offer.credential_offer_uri)).data;
			}
			console.log("Credential offer = ", credential_offer)

			const credentialIssuerURL = credential_offer.credential_issuer as string;
			lp = (await getLegalPersonByUrl(credentialIssuerURL)).unwrap();
			issuerUrlString = lp.url;
			issuer_state = credential_offer?.grants.authorization_code?.issuer_state 

		}

		if (!issuerUrlString) {
			throw "No issuer url is defined"
		}

		

		const credentialIssuerMetadata = (await axios.get(issuerUrlString + "/.well-known/openid-credential-issuer")).data as CredentialIssuerMetadata;
		console.log("Credential issuer metadata")
		console.dir(credentialIssuerMetadata, { depth: null })
		const authorizationServerConfig = (await axios.get(credentialIssuerMetadata.authorization_server + "/.well-known/openid-configuration")).data;

		// all credential supported will be added into the authorization details by default
		const authorizationDetails: CredentialSupportedJwtVcJson[] = (credential_offer ? credential_offer.credentials : credentialIssuerMetadata.credentials_supported)
		.map((cred_sup) => {
			return {
				format: cred_sup.format,
				types: cred_sup.types,
				type: "openid_credential",
				locations: [ credentialIssuerMetadata.credential_issuer ]
			};
		});

		if (credential_offer && credential_offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]) {
			this.states.set(userDid, {
				userDid,
				credentialIssuerMetadata: credentialIssuerMetadata,
				openidConfiguration: authorizationServerConfig,
				legalPerson: lp,
				authorization_details: authorizationDetails,
				issuer_state: issuer_state,
				grant_type: GrantType.PRE_AUTHORIZED_CODE,
				code: credential_offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
			});
			const user_pin_required = credential_offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["user_pin_required"];
			console.log("Redirecting to ... ", config.walletClientUrl + `?preauth=true&ask_for_pin=${user_pin_required}`)
			return { redirect_to: config.walletClientUrl + `?preauth=true&ask_for_pin=${user_pin_required}` }
		}
		
		

		

		
		const authorizationRequestURL = new URL(authorizationServerConfig.authorization_endpoint);
		authorizationRequestURL.searchParams.append("scope", "openid");
		authorizationRequestURL.searchParams.append("client_id", userDid);
		
		authorizationRequestURL.searchParams.append("redirect_uri", config.walletClientUrl);

		authorizationRequestURL.searchParams.append("authorization_details", JSON.stringify(authorizationDetails));
		const code_verifier = generateCodeVerifier();
		const code_challenge = await generateCodeChallengeFromVerifier(code_verifier);
		authorizationRequestURL.searchParams.append("code_challenge", code_challenge);
		authorizationRequestURL.searchParams.append("code_challenge_method", "S256");
		authorizationRequestURL.searchParams.append("response_type", "code");
		authorizationRequestURL.searchParams.append("issuer_state", issuer_state);

		authorizationRequestURL.searchParams.append("client_metadata", JSON.stringify(client_metadata));
		this.states.set(userDid, {
			userDid,
			authorization_details: authorizationDetails,
			credentialIssuerMetadata: credentialIssuerMetadata,
			openidConfiguration: authorizationServerConfig,
			legalPerson: lp,
			code_verifier: code_verifier,
			issuer_state: issuer_state,
			grant_type: GrantType.AUTHORIZATION_CODE
		})
		console.log("generateAuthorizationRequest \n\t", authorizationRequestURL)
		return { redirect_to: authorizationRequestURL.toString() };
	}



	public async requestCredentialsWithPreAuthorizedGrant(userDid: string, user_pin: string) {
		let state = this.states.get(userDid)
		state = { ...state, user_pin: user_pin };
		this.states.set(userDid, state); // save state with pin

		this.tokenRequest(state).then(tokenResponse => {
			state = { ...state, tokenResponse }
			this.states.set(userDid, state);
			this.credentialRequests(userDid, state).catch(e => {
				console.error("Credential requests failed with error : ", e)
			});
		})
	}

	/**
	 * 
	 * @param authorizationResponseURL
	 * @throws
	 */
	public async handleAuthorizationResponse(userDid: string, authorizationResponseURL: string): Promise<Result<void, IssuanceErr | void>> {
		const currentState = this.states.get(userDid);
		if (!currentState) {
			return Err(IssuanceErr.STATE_NOT_FOUND);
		}

		const url = new URL(authorizationResponseURL);
		const code = url.searchParams.get('code');
		if (!code) {
			throw new Error("Code not received");
		}
		let newState = { ...currentState, code };
		this.states.set(userDid, newState);

		const tokenResponse = await this.tokenRequest(newState);
		newState = { ...newState, tokenResponse }
		this.states.set(userDid, newState);
		try {
			return await this.credentialRequests(userDid, newState);
		} catch (e) {
			console.error("Credential requests failed with error : ", e)
		}
	}



	/**
	 * @throws
	 * @param state 
	 * @returns 
	 */
	private async tokenRequest(state: IssuanceState): Promise<TokenResponseSchemaType> {
		console.info("State = ", state)
		// Not adding authorization header
		// const basicAuthorizationB64 = Buffer.from(`${state.legalPerson.client_id}:${state.legalPerson.client_secret}`).toString("base64");
		const httpHeader = { 
			// "authorization": `Basic ${basicAuthorizationB64}`,
			"Content-Type": "application/x-www-form-urlencoded"
		};

		const data = new URLSearchParams();
		switch (state.grant_type) {
		case GrantType.AUTHORIZATION_CODE:
			data.append('grant_type', 'authorization_code');
			data.append('code', state.code);
			data.append('redirect_uri', config.walletClientUrl);
			data.append('code_verifier', state.code_verifier);
			const user = (await getUserByDID(state.userDid)).unwrap();
			data.append('client_id', user.did);
			break;
		case GrantType.PRE_AUTHORIZED_CODE:
			data.append('grant_type', 'urn:ietf:params:oauth:grant-type:pre-authorized_code');
			data.append('pre-authorized_code', state.code);
			data.append('user_pin', state.user_pin);
			break;
		default:
			break;
		}

		
		// const clientAssertionJWT = await new SignJWT({})
		// 	.setProtectedHeader({ alg: wallet.key.alg, kid: wallet.key.did + "#" + wallet.key.did.split(':')[2] })
		// 	.setAudience(state.legalPerson.url)
		// 	.setIssuedAt()
		// 	.setIssuer(user.did)
		// 	.setSubject(user.did)
		// 	.setExpirationTime('30s')
		// 	.setJti(randomUUID())
		// 	.sign(await importJWK(wallet.getPrivateKey(), wallet.key.alg));


		// data.append('client_assertion', clientAssertionJWT);
		// data.append('client_assertion_method', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');

		console.log("Openid config = ", state.openidConfiguration)

		const tokenEndpoint = state.openidConfiguration.token_endpoint;
		try {
			const httpResponse = await axios.post(tokenEndpoint, data, { headers: httpHeader });
			const httpResponseBody = httpResponse.data as TokenResponseSchemaType;
			return httpResponseBody;
		}
		catch(err) {
			if (err.response) {
				console.error("HTTP response error body = ", err.response.data)
			}
			throw "Token Request failed"
		}

	}

	/**
	 * @throws
	 */
	private async credentialRequests(userDid: string, state: IssuanceState): Promise<Result<void, void>> {
		console.log("State = ", state)

		const httpHeader = {
			"authorization": `Bearer ${state.tokenResponse.access_token}`,
		};

		const c_nonce = state.tokenResponse.c_nonce;
		const res = await this.walletKeyStore.generateOpenid4vciProof(userDid, state.credentialIssuerMetadata.credential_issuer, c_nonce);
		if (!res.ok) {
			if (res.val === WalletKeystoreErr.KEYS_UNAVAILABLE) {
				return Err.EMPTY;
			}
		}

		const { proof_jwt } = res.val;
		const credentialEndpoint = state.credentialIssuerMetadata.credential_endpoint;

		let httpResponsePromises = state.authorization_details.map((authzDetail) => {
			const httpBody = {
				proof: {
					proof_type: "jwt",
					jwt: proof_jwt
				},
				...authzDetail
			}
			return axios.post(credentialEndpoint, httpBody, { headers: httpHeader });
		})

		const responses = await Promise.allSettled(httpResponsePromises);
		let credentialResponses = responses
			.filter(res => res.status == 'fulfilled')
			.map((res) =>
				res.status == "fulfilled" ? res.value.data as CredentialResponseSchemaType : null
			);

		// Prevent duplicate credential acceptance
		this.states.delete(userDid);

		for (const cr of credentialResponses) {
			this.checkConstantlyForPendingCredential(state, cr.acceptance_token);
		}

		// remove the ones that are for deferred endpoint
		credentialResponses = credentialResponses.filter((cres) => !cres.acceptance_token);

		for (const response of credentialResponses) {
			console.log("Response = ", response)
			this.handleCredentialStorage(state, response);
		}
		console.log("=====FINISHED OID4VCI")
		return Ok.EMPTY;
	}

	// Deferred Credential only
	private async checkConstantlyForPendingCredential(state: IssuanceState, acceptance_token: string) {
		const defferedCredentialReqHeader = { 
			"authorization": `Bearer ${acceptance_token}`,
		};
		
		axios.post(state.credentialIssuerMetadata.deferred_credential_endpoint,
			{}, 
			{ headers: defferedCredentialReqHeader } )
			.then((res) => {
				this.handleCredentialStorage(state, res.data);
			})
			.catch(err => {
				setTimeout(() => {
					this.checkConstantlyForPendingCredential(state, acceptance_token);
				}, 2000);
			})

		
	}

	private async handleCredentialStorage(state: IssuanceState, credentialResponse: CredentialResponseSchemaType) {
		const userRes = await getUserByDID(state.userDid);
		if (userRes.err) {
			return;
		}
		const user = userRes.unwrap();

		const { legalPerson } = state;
		console.log("Legal person  = ", legalPerson)
		const credentialPayload = JSON.parse(base64url.decode(credentialResponse.credential.split('.')[1]))
		const type = credentialPayload.vc.type as string[];
		const metadata = (await axios.get(legalPerson.url + "/.well-known/openid-credential-issuer")).data as CredentialIssuerMetadata;
		
		
		let logoUrl = config.url + "/alt-vc-logo.png";
		let background_color = "#D3D3D3";

		const supportedCredential = metadata.credentials_supported.filter(cs => cs.format == credentialResponse.format && _.isEqual(cs.types, type))[0];
		if (supportedCredential) {
			if (supportedCredential.display && 
					supportedCredential.display.length != 0 &&
					supportedCredential.display[0]?.logo &&
					supportedCredential.display[0]?.logo?.url) {
					
				logoUrl = supportedCredential.display[0].logo.url;

			}

			if (supportedCredential.display && supportedCredential.display.length != 0 && supportedCredential.display[0].background_color) {
				background_color = supportedCredential.display[0].background_color;
			}
		}


		createVerifiableCredential({
			issuerDID: credentialPayload.iss,
			credentialIdentifier: credentialPayload.jti,
			credential: credentialResponse.credential,
			holderDID: user.did,
			issuerURL: legalPerson.url,
			logoURL: logoUrl,
			format: credentialResponse.format as VerifiableCredentialFormat,
			backgroundColor: background_color,
			issuanceDate: new Date(credentialPayload.iat * 1000),
			issuerFriendlyName: legalPerson.friendlyName
		}).then(success => { // when credential is stored, then send notification
			if (success.err) {
				return;
			}
			console.log("FCM token = ", user.fcmToken)
			if (user.fcmToken)
				sendPushNotification(user.fcmToken.toString(), "New Credential", "A new verifiable credential is in your wallet").catch(err => {
					console.log("Failed to send notification")
					console.log(err)
				});
			if (user.browserFcmToken)
				sendPushNotification(user.browserFcmToken.toString(), "New Credential", "A new verifiable credential is in your wallet").catch(err => {
					console.log("Failed to send notification")
					console.log(err)
				});
		});

	}

	private static generatePresentableFormat(credentialSubjectMetadata: any, verifiableCredential: any): any {
		return getLeafNodesWithPath(verifiableCredential, credentialSubjectMetadata)
	}
}

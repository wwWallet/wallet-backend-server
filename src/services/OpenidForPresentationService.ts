import axios from "axios";
import { JSONPath } from "jsonpath-plus";
import base64url from "base64url";
import qs from "qs";
import { inject, injectable } from "inversify";
import "reflect-metadata";
import { z } from 'zod';
import { Err, Ok, Result } from "ts-results";

import { InputDescriptorType, Verify } from "@gunet/ssi-sdk";
import { OpenidCredentialReceiving, OutboundCommunication, WalletKeystore, WalletKeystoreErr, WalletKeystoreRequest } from "./interfaces";
import { TYPES } from "./types";
import { OutboundRequest } from "./types/OutboundRequest";
import { getAllVerifiableCredentials } from "../entities/VerifiableCredential.entity";
import { createVerifiablePresentation } from "../entities/VerifiablePresentation.entity";
import { getUserByUsername } from "../entities/user.entity";


type PresentationDefinition = {
	id: string,
	input_descriptors: InputDescriptor[]
}


const authorizationRequestSchema = z.object({
	client_id: z.string(),
	response_type: z.string(),
	scope: z.string(),
	redirect_uri: z.string(),
	request: z.string().optional()
});


type InputDescriptor = {
	id: string,
	constraints: Constraint[],
	name?: string,
	purpose?: string,
	format?: any
}

type Constraint = {
	fields: Field[],
	limit_disclosure?: "required" | "preferred"
}

type Field = {
	path: string[],
	id?: string,
	purpose?: string,
	name?: string,
	filter?: string,
	optional?: boolean
}

type VerificationState = {
	presentation_definition?: PresentationDefinition;
	audience?: string;
	nonce?: string;
	redirect_uri?: string;
	state?: string;
}


@injectable()
export class OpenidForPresentationService implements OutboundCommunication {
	public static readonly identifier = "OpenidForPresentationService"

	states = new Map<string, VerificationState>();


	constructor(
		@inject(TYPES.WalletKeystore) private walletKeystore: WalletKeystore,
		@inject(TYPES.OpenidForCredentialIssuanceService) private OpenidCredentialReceivingService: OpenidCredentialReceiving
	) { }


	async handleRequest(username: string, requestURL: string, id_token: string | null): Promise<Result<OutboundRequest, WalletKeystoreRequest>> {
		try {
			return await this.parseIdTokenRequest(username, requestURL, id_token);
		}
		catch(err) {
		}

		try {
			const url = new URL(requestURL);
			const params = new URLSearchParams(url.search);
			const paramEntries = [...params.entries()];

			const jsonParams = Object.fromEntries(paramEntries);
			authorizationRequestSchema.parse(jsonParams); // will throw error if input is not conforming to the schema

			const { conformantCredentialsMap, verifierDomainName } = await this.parseAuthorizationRequest(username, requestURL);
			return Ok({
				conformantCredentialsMap: conformantCredentialsMap,
				verifierDomainName: verifierDomainName
			});
		}
		catch(err) {

		}

		return Ok({ });
	}


	async sendResponse(username: string, selection: Map<string, string>, vpjwt: string | null): Promise<Result<{ redirect_to?: string, error?: Error }, WalletKeystoreRequest>> {
		try {
			return await this.generateAuthorizationResponse(username, selection, vpjwt)
		}
		catch(err) {
			console.error("Failed to generate authorization response.\nError details: ", err);
			return Ok({ error: new Error("Failed to generate authorization response") });
		}
	}




	private async parseIdTokenRequest(username: string, authorizationRequestURL: string, id_token: string | null): Promise<Result<{ redirect_to: string }, WalletKeystoreRequest>> {
		console.log("Username2: ", username)

		if (id_token) {
			const currentState = this.states.get(username);
			return Ok(await this.finishParseIdTokenRequest(username, currentState.state, currentState.redirect_uri, id_token));
		}

		let client_id: string,
			redirect_uri: string,
			nonce: string,
			presentation_definition: PresentationDefinition | null,
			state: string | null;

		console.log("Pure params = ", new URL(authorizationRequestURL))
		try {
			const searchParams = await this.authorizationRequestSearchParams(authorizationRequestURL);
			console.log("SEARCH params = ", searchParams)
			client_id = searchParams.client_id;
			redirect_uri = searchParams.redirect_uri;
			nonce = searchParams.nonce;
			presentation_definition = searchParams.presentation_definition
			state = searchParams.state;
		}
		catch(error) {
			throw new Error(`Error fetching authorization request search params: ${error}`);
		}

		if (presentation_definition) {
			throw "This is not an id token request"
		}

		const currentState = this.states.get(username);
		this.states.set(username, {
			...currentState,
			audience: client_id,
			nonce,
			redirect_uri,
			state,
		});
		const idTokenResult = await this.walletKeystore.createIdToken(username, nonce, client_id);
		if (idTokenResult.ok) {
			const { id_token } = idTokenResult.val;
			return Ok(await this.finishParseIdTokenRequest(username, state, redirect_uri, id_token));
		} else if (idTokenResult.val === WalletKeystoreErr.KEYS_UNAVAILABLE) {
			return Err({ action: "createIdToken", nonce, audience: client_id });
		}
	}

	private async finishParseIdTokenRequest(username: string, state: string, redirect_uri: string, id_token: string): Promise<{ redirect_to: string }> {
		// const id_token = await new SignJWT({ nonce: nonce })
		// 	.setAudience(client_id)
		// 	.setIssuedAt()
		// 	.setIssuer(did)
		// 	.setSubject(did)
		// 	.setExpirationTime('1h')
		// 	.setProtectedHeader({ kid: did+"#"+did.split(":")[2], typ: 'JWT', alg: walletKey.alg })
		// 	.sign(await importJWK(walletKey.privateKey, walletKey.alg));

		const { issuer_state } = await this.OpenidCredentialReceivingService.getIssuerState(username);

		const params = {
			id_token,
			state: state,
			issuer_state: issuer_state
		};

		console.log("Params = ", params)
		console.log("RedirectURI = ", redirect_uri)
		const encodedParams = qs.stringify(params);
		const { newLocation } = await axios.post(redirect_uri, encodedParams, { maxRedirects: 0, headers: { "Content-Type": "application/x-www-form-urlencoded" }})
			.then(success => {
				console.log("url = ", success.config.headers)
				console.log("body = ", success.data)
				console.log(success.status)
				const msg = {
					error: "Direct post error",
					error_description: "Failed to redirect after direct post"
				};
				console.error(msg);
				// console.log("Sucess = ", success.data)
				return { newLocation: null }
			})
			.catch(e => {
				console.log("ERR");
				console.log("UNKNOWN")
				if (e.response) {
					console.log("UNKNOWN = ", e.response.data)

					if (e.response.headers.location) {
						console.log("Loc: ", e.response.headers.location);
						const newLocation = e.response.headers.location as string;
						console.error("Body of Error = ", e.response.data)
						const url = new URL(newLocation)
						console.log("Pure url of loc: ", url)
						return { newLocation }
					}
					else {
						return { newLocation: null }
					}

				}
			});
		console.log("New loc : ", newLocation)
		// check if newLocation is null
		return { redirect_to: newLocation }
	}

	/**
	 * @throws
	 * @param did 
	 * @param username 
	 * @param authorizationRequestURL 
	 * @returns 
	 */
	private async parseAuthorizationRequest(username: string, authorizationRequestURL: string): Promise<{conformantCredentialsMap: Map<string, string[]>, verifierDomainName: string}> {
		console.log("Request username = ", username)
		const { did } = (await getUserByUsername(username)).unwrap();
		let client_id: string,
				redirect_uri: string,
				nonce: string,
				presentation_definition: PresentationDefinition | null,
				state: string | null;
		try {
			console.log("All search params = ", new URL(authorizationRequestURL).searchParams)
			const params = new URL(authorizationRequestURL).searchParams;
			// const searchParams = await this.authorizationRequestSearchParams(authorizationRequestURL);
			client_id = params.get('client_id');
			redirect_uri = params.get('redirect_uri');
			nonce = params.get('nonce');
			state = params.get('state');
			presentation_definition = JSON.parse(params.get('presentation_definition'));
			if (!presentation_definition) {
				const url = params.get('presentation_definition_uri');
				try {
					presentation_definition = (await axios.get(url)).data;
				}
				catch(err) {
					throw "There is no way to get presentation definition";
				}

			}
		}
		catch(error) {
			throw new Error(`Error fetching authorization request search params: ${error}`);
		}
		
		this.states.set(username, {
			presentation_definition,
			audience: client_id,
			nonce,
			redirect_uri,
			state
		});


		console.log("State = ", this.states.get(username))


		console.log("Definition = ", presentation_definition)
		
		let descriptors: InputDescriptorType[];
		try {
			descriptors = JSONPath({
				path: "$.input_descriptors[*]",
				json: presentation_definition,
			}) as InputDescriptorType[];
		}
		catch(error) {
			throw new Error(`Error fetching input descriptors from presentation_definition: ${error}`);
		}

		try {
			const verifiableCredentialsRes = await getAllVerifiableCredentials(did);
			if (verifiableCredentialsRes.err) {
				throw "Failed to fetch credentials"
			}
			const vcList = verifiableCredentialsRes.unwrap();
			console.log("Descriptors = ")
			console.dir(descriptors, { depth: null });
			console.log("VC list size = ", vcList.length)


			const mapping = new Map<string, string[]>();
			for (const descriptor of descriptors) {
				console.log("Descriptor :")
				console.dir(descriptor, { depth: null })
				const conformingVcList = []
				for (const vc of vcList) {
					if (Verify.verifyVcJwtWithDescriptor(descriptor, vc.credential)) {
						conformingVcList.push(vc.credentialIdentifier);
					}
				}
				if (conformingVcList.length == 0) {
					// throw "No conformant credential was found for at least one descriptor";
					continue;
				}
				mapping.set(descriptor.id, [ ...conformingVcList ]);
			}
			const verifierDomainName = new URL(redirect_uri).hostname;
			if (mapping.size == 0) {
				console.info("Credentials don't satisfy any descriptor")
				throw "Credentials don't satisfy any descriptor"
			}
			console.log("Mapping = ", mapping)
			return { conformantCredentialsMap: mapping, verifierDomainName }
		}
		catch(error) {
			throw new Error(`Error verifying credentials meeting requirements from input_descriptors: ${error}`)
		}
	}


	private async generateVerifiablePresentation(selectedVC: string[], username: string, vpjwt: string | null): Promise<Result<string, WalletKeystoreRequest>> {
		if (vpjwt) {
			return Ok(vpjwt);
		}

		const fetchedState = this.states.get(username);
		console.log(fetchedState);
		const {audience, nonce} = fetchedState;
		const result = await this.walletKeystore.signJwtPresentation(username, nonce, audience, selectedVC);
		if (!result.ok) {
			return Err({
				action: "signJwtPresentation",
				nonce,
				audience,
				verifiableCredentials: selectedVC,
			});
		}

		return Ok(result.val.vpjwt);
	}
	
	private async generateAuthorizationResponse(username: string, selection: Map<string, string>, vpjwt: string | null): Promise<Result<{ redirect_to: string }, WalletKeystoreRequest>> {
		console.log("Response username = ", username)
		const allSelectedCredentialIdentifiers = Array.from(selection.values());

		const { did } = (await getUserByUsername(username)).unwrap();
		console.log("Verifiable credentials map = ", selection)
		let vcListRes = await getAllVerifiableCredentials(did);
		if (vcListRes.err) {
			throw "Failed to fetch credentials"
		}
		const filteredVCEntities = vcListRes.unwrap()
			.filter((vc) => 
				allSelectedCredentialIdentifiers.includes(vc.credentialIdentifier)
			);
		const filteredVCJwtList = filteredVCEntities.map((vc) => vc.credential);

		try {
			const vp_token_result = await this.generateVerifiablePresentation(filteredVCJwtList, username, vpjwt);
			if (vp_token_result.err) {
				return Err(vp_token_result.val);
			}

			const vp_token: string = vp_token_result.val as string;
			const {presentation_definition, redirect_uri, state} = this.states.get(username);
			// console.log("vp token = ", vp_token)
			// console.log("Presentation definition from state is = ");
			// console.dir(presentation_definition, { depth: null });
			const matchesPresentationDefinitionRes = await Verify.getMatchesForPresentationDefinition(vp_token, presentation_definition);
			if(matchesPresentationDefinitionRes == null) {
				throw new Error("Credentials presented do not match presentation definition requested");
			}
	
			const {presentationSubmission} = matchesPresentationDefinitionRes;
	
			// let counter = 0

			// for (let i = 0; i < presentationSubmission.descriptor_map.length; i++) {
			// 	presentationSubmission.descriptor_map[i].path_nested["id"] = `${randomUUID()}`
			// }
			console.log("Submission: ")
			console.dir(presentationSubmission, { depth: null });

			const directPostPayload = {
				vp_token: vp_token,
				presentation_submission: JSON.stringify(presentationSubmission),
				state: state
			};
			const { newLocation } = await axios.post(redirect_uri, qs.stringify(directPostPayload), {
				maxRedirects: 0,
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
				}
			}).then(result => {
				return { newLocation: null }
			}).catch(e => {
				if (e.response) {
					console.log("Body of response = ", e.response.data)
					if (e.response.headers.location) { // if new location is defined
						console.log("Loc: ", e.response.headers.location);
						const newLocation = e.response.headers.location as string;
						console.error("Body of Error = ", e.response.data)
						const url = new URL(newLocation)
						console.log("Pure url of loc: ", url)
						const errorMsg = url.searchParams.get('error');
						const errorDesc = url.searchParams.get('error_description');
						console.log("error description = ", errorDesc)
						return { newLocation }
					}
					else {
						return { newLocation: null };
					}

				}
			});

			if (!newLocation) {
				throw "Direct post failed";
			}
			const vpPayload = JSON.parse(base64url.decode(vp_token.split('.')[1]));
			console.log("Credential identifiers = ", filteredVCEntities.map((vc) => vc.credentialIdentifier))
			createVerifiablePresentation({
				holderDID: did,
				issuanceDate: vpPayload.vp.issuanceDate,
				presentation: vp_token,
				includedVerifiableCredentialIdentifiers: filteredVCEntities.map((vc) => vc.credentialIdentifier),
				presentationIdentifier: vpPayload.jti,
				presentationSubmission: presentationSubmission,
				audience: new URL(vpPayload.aud).hostname,
				format: "jwt_vp"
			});


			return Ok({ redirect_to: newLocation });
		}
		catch(error) {
			throw new Error(`Error generating Verifiable Presentation: ${error}`);
		}
	}

	/**
	 * Extract a Presentation Definition contained in an Authorization Request URL.
	 * The Presentation Definition may be contained as a plain, uri-encoded JSON object in the presentation_definition parameter,
	 * or as the response of an API indicated on the presentation_definition_uri parameter.
	 * Usage of both presentation_definition and presentation_definition_uri parameters is invalid.
	 * The function checks which of the two url parameters is present, and handles fetching appropriately.
	 * After a presentation definition has been fetched, its validity is examined.
	 * If the presentation definition is valid, it is returned.
	 * @param authorizationRequestURL
	 * @returns PresentationDefinition
	 * @throws InvalidAuthorizationRequestURLError
	 * @throws InvalidPresentationDefinitionURIError
	 * @throws InvalidPresentationDefinitionError
	 */
	private async fetchPresentationDefinition(authorizationRequestURL: URL): Promise<PresentationDefinition> {

		const searchParams = authorizationRequestURL.searchParams;

		let presentation_definition = searchParams.get("presentation_definition");
		let presentation_definition_uri = searchParams.get("presentation_definition_uri");

		console.log("Presentation definition = ", presentation_definition)
		const request = searchParams.get("request");

		const requestPayload = request ? JSON.parse(base64url.decode(request.split('.')[1])) : null;
		if(requestPayload && requestPayload.presentation_definition)
			presentation_definition = requestPayload.presentation_definition;
		if(requestPayload && requestPayload.presentation_definition_uri)
			presentation_definition_uri = requestPayload.presentation_definition_uri;

		console.log(presentation_definition_uri, presentation_definition);

		if(presentation_definition && presentation_definition_uri) {
			const error = "Both presentation_definition and presentation_definition_uri parameters in authorization request URL";
			console.error(error);
			throw new Error(`Invalid Authorization Request URL: ${error}`);
		}

		if(!presentation_definition && !presentation_definition_uri) {
			const error = "Neither presentation_definition nor presentation_definition_uri parameters in authorization request URL";
			console.error(error);
			throw new Error(`Invalid Authorization Request URL: ${error}`);
		}

		let presentationDefinition: PresentationDefinition;
		if(presentation_definition) {
			presentationDefinition = JSON.parse(presentation_definition);
			console.log("Parsed presentation definition = " , presentationDefinition)
		}
		else {

			try {
				presentationDefinition = await this.fetchPresentationDefinitionUri(presentation_definition_uri);
			}
			catch(error) {
				console.error(`Error fetching presentation definition from URI: ${error}`);
				throw new Error(`Error fetching presentation definition from URI: ${error}`);
			}
		}

		// TODO: Check Presentation Definition validity
		return presentationDefinition;

	}

	private async fetchPresentationDefinitionUri(uri: string): Promise<PresentationDefinition> {

		// test if PresentationDefinitionUri is malformed string
		try {
			new URL(uri);
		}
		catch(error) {
			console.error(`Presentation Definition URI is invalid.`)
			throw new Error(`Invalid PresentationDefinitionURI: ${error}`);
		}

		const fetchPresentationDefinitionRes = await axios.get(uri.toString());
		if(fetchPresentationDefinitionRes.status !== 200) {
			console.error(`Error fetching Presentation Definition from URI: ${fetchPresentationDefinitionRes.data}`);
			throw new Error(`Error fetching Presentation Definition from URI`);
		}
		
		return fetchPresentationDefinitionRes.data;
	}


	/**
	 * Handle Authorization Request search Parameters.
	 * @param authorizationRequest a string of the authorization request URL
	 * @returns An object containing Authorization Request Parameters
	 */
	private async authorizationRequestSearchParams(authorizationRequest: string) {
	
		// let response_type, client_id, redirect_uri, scope, response_mode, presentation_definition, nonce;

		// Attempt to convert authorizationRequest to URL form, in order to parse searchparams easily
		// An error will be thrown if the URL is invalid
		let authorizationRequestUrl: URL;
		try {
			authorizationRequestUrl = new URL(authorizationRequest);
		}
		catch(error) {
			throw new Error(`Invalid Authorization Request URL: ${error}`);
		}

		// const variables are REQUIRED authorization request parameters and they must exist outside the "request" parameter
		const response_type = authorizationRequestUrl.searchParams.get("response_type");
		const client_id = authorizationRequestUrl.searchParams.get("client_id");
		const redirect_uri = authorizationRequestUrl.searchParams.get("redirect_uri");
		const scope = authorizationRequestUrl.searchParams.get("scope");
		let response_mode = authorizationRequestUrl.searchParams.get("response_mode");
		let nonce = authorizationRequestUrl.searchParams.get("nonce");
		let state = authorizationRequestUrl.searchParams.get("state") as string | null;
		let request_uri = authorizationRequestUrl.searchParams.get("request_uri") as string | null;
		const request = authorizationRequestUrl.searchParams.get("request");

	
		try {
			if(request) {
				let requestPayload: any;
				try {
					requestPayload = JSON.parse(base64url.decode(request.split('.')[1]));
				}
				catch(error) {
					throw new Error(`Invalid Request parameter: Request is not a jwt. Details: ${error}`);
				}

				if(requestPayload.response_type && requestPayload.response_type !== response_type) {
					throw new Error('Request JWT response_type and authorization request response_type search param do not match');
				}

				if(requestPayload.scope && requestPayload.scope !== scope) {
					throw new Error('Request JWT scope and authorization request scope search param do not match');
				}

				if(requestPayload.client_id && requestPayload.client_id !== client_id) {
					throw new Error('Request JWT client_id and authorization request client_id search param do not match');
				}

				if(requestPayload.redirect_uri && requestPayload.redirect_uri !== redirect_uri) {
					throw new Error('Request JWT redirect_uri and authorization request redirect_uri search param do not match');
				}

				if(requestPayload.response_mode)
					response_mode = requestPayload.response_mode;
				
				if(requestPayload.nonce)
					nonce = requestPayload.nonce
			}
		}
		catch(error) {
			throw new Error(`Error decoding request search parameter: ${error}`);
		}

		let presentation_definition: PresentationDefinition | null;
		try {
			presentation_definition = await this.fetchPresentationDefinition(authorizationRequestUrl);
		}
		catch(error) {
			console.error(`Error fetching Presentation Definition: ${error}`);
		}

		// Finally, check if all required variables have been given

		if(response_type !== "vp_token" && response_type !== "id_token") {
			console.error(`Expected response_type = vp_token or id_token, got ${response_type}`);
			throw new Error('Invalid response type');
		}

		if(client_id === null) {
			throw new Error('Client ID not given');
		}

		if(redirect_uri === null) {
			throw new Error('Redirect URI not given');
		}

		if(scope !== "openid") {
			console.error(`Expected scope = openid, got ${scope}`);
			throw new Error('Invalid scope');
		}

		if(response_mode !== "direct_post") {
			console.error(`Expected response_mode = direct_post, got ${response_mode}`);
			throw new Error('Invalid response mode');
		}

		if(nonce === null) {
			throw new Error('Nonce not given');
		}

		// if(!presentation_definition) {
		// 	throw new Error('Presentation Definition not given');
		// }

		return {
			client_id,
			response_type,
			scope,
			redirect_uri,
			response_mode,
			nonce,
			presentation_definition,
			state,
			request_uri
		}

	}

}

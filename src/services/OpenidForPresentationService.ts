import axios from "axios";
import { JSONPath } from "jsonpath-plus";
import base64url from "base64url";
import qs from "qs";
import { inject, injectable } from "inversify";
import "reflect-metadata";
import { z } from 'zod';
import { Err, Ok, Result } from "ts-results";

import { InputDescriptorType, Verify } from "@wwwallet/ssi-sdk";
import { HandleOutboundRequestError, OutboundCommunication, SendResponseError, WalletKeystore } from "./interfaces";
import { TYPES } from "./types";
import { OutboundRequest } from "./types/OutboundRequest";
import { getAllVerifiableCredentials } from "../entities/VerifiableCredential.entity";
import { createVerifiablePresentation } from "../entities/VerifiablePresentation.entity";
import { getUser, UserId } from "../entities/user.entity";
import { VerifierRegistryService } from "./VerifierRegistryService";
import { randomUUID, createHash } from "node:crypto";
import config from "../../config";
import { WalletKeystoreRequest, SignatureAction } from "./shared.types";
import {
	HasherAlgorithm,
	HasherAndAlgorithm,
	SdJwt,
} from '@sd-jwt/core';

type PresentationDefinition = {
	id: string,
	format: any;
	input_descriptors: InputDescriptor[]
}



const authorizationRequestSchema = z.object({
	client_id: z.string(),
	response_type: z.string(),
	scope: z.string(),
	redirect_uri: z.string().optional(),
	response_uri: z.string().optional(),
	request: z.string().optional()
});


type InputDescriptor = {
	id: string,
	constraints: {
		fields: Field[];
	},
	name?: string,
	purpose?: string,
	format?: any
}

// type Constraint = {
// 	fields: Field[],
// 	limit_disclosure?: "required" | "preferred"
// }

type Field = {
	path: string[],
	id?: string,
	purpose?: string,
	name?: string,
	filter?: string,
	optional?: boolean
}

type VerificationState = {
	camera_was_used?: boolean;
	holder_state?: string;
	presentation_definition?: PresentationDefinition;
	audience?: string;
	nonce?: string;
	response_uri?: string;
	state?: string;
}


@injectable()
export class OpenidForPresentationService implements OutboundCommunication {

	// key: UserEntity.uuid
	states = new Map<string, VerificationState>();


	constructor(
		@inject(TYPES.WalletKeystoreManagerService) private walletKeystoreManagerService: WalletKeystore,
		@inject(TYPES.VerifierRegistryService) private verifierRegistryService: VerifierRegistryService,
	) { }

	async initiateVerificationFlow(userId: UserId, verifierId: number, scopeName: string): Promise<{ redirect_to?: string }> {
		const verifier = (await this.verifierRegistryService.getAllVerifiers()).filter(ver => ver.id == verifierId)[0];
		console.log("User id = ", userId)
		const userFetchRes = await getUser(userId);
		if (userFetchRes.err) {
			return {};
		}
		const holder_state = randomUUID();
		this.states.set(userId.id, { holder_state });

		const user = userFetchRes.unwrap();
		const url = new URL(verifier.url);
		url.searchParams.append("scope", "openid " + scopeName);
		url.searchParams.append("redirect_uri", config.walletClientUrl);
		url.searchParams.append("client_id", user.did);
		url.searchParams.append("response_type", "code");
		url.searchParams.append("state", holder_state);
		return { redirect_to: url.toString() };
	}

	async handleRequest(userId: UserId, requestURL: string, camera_was_used: boolean): Promise<Result<OutboundRequest, WalletKeystoreRequest | HandleOutboundRequestError>> {

		try {
			const url = new URL(requestURL);
			const params = new URLSearchParams(url.search);
			const paramEntries = [...params.entries()];

			const jsonParams = Object.fromEntries(paramEntries);
			authorizationRequestSchema.parse(jsonParams); // will throw error if input is not conforming to the schema
			this.states.set(userId.id, { camera_was_used: camera_was_used })
			const result = await this.parseAuthorizationRequest(userId, requestURL);
			if (result.err) {
				return Err(result.val);
			}
			const { conformantCredentialsMap, verifierDomainName } = result.unwrap();
			console.log("Handle VP Req = " , { conformantCredentialsMap, verifierDomainName })
			return Ok({
				conformantCredentialsMap: conformantCredentialsMap,
				verifierDomainName: verifierDomainName
			});
		}
		catch(err) {
			console.error(err);
		}

		return Ok({ });
	}


	async sendResponse(userId: UserId, selection: Map<string, string>): Promise<Result<{ redirect_to?: string }, WalletKeystoreRequest | SendResponseError>> {
		try {
			return await this.generateAuthorizationResponse(userId, selection)
		}
		catch(err) {
			console.error("Failed to generate authorization response.\nError details: ", err);
			return Err(SendResponseError.SEND_RESPONSE_ERROR);
		}
	}

	private async parseAuthorizationRequest(userId: UserId, authorizationRequestURL: string): Promise<Result<{conformantCredentialsMap: Map<string, { credentials: string[], requestedFields: string[] }>, verifierDomainName: string}, HandleOutboundRequestError>> {
		console.log("parseAuthorizationRequest userId = ", userId)
		let client_id: string,
			response_uri: string,
			nonce: string,
			presentation_definition: PresentationDefinition | null,
			state: string | null;
		try {
			console.log("All search params = ", new URL(authorizationRequestURL).searchParams)
			const params = new URL(authorizationRequestURL).searchParams;
			// const searchParams = await this.authorizationRequestSearchParams(authorizationRequestURL);
			client_id = params.get('client_id');
			response_uri = params.get('response_uri') ?? params.get('redirect_uri');
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
		const currentState = this.states.get(userId.id);
		this.states.set(userId.id, {
			...currentState,
			presentation_definition,
			audience: client_id,
			nonce,
			response_uri,
			state
		});


		console.log("State = ", this.states.get(userId.id))


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

		const user = (await getUser(userId)).unwrap();

		try {
			const verifiableCredentialsRes = await getAllVerifiableCredentials(user.did);
			if (verifiableCredentialsRes.err) {
				throw "Failed to fetch credentials"
			}
			const vcList = verifiableCredentialsRes.unwrap();
			console.log("Descriptors = ")
			console.dir(descriptors, { depth: null });
			console.log("VC list size = ", vcList.length)


			const mapping = new Map<string, { credentials: string[], requestedFields: string[] }>();
			for (const descriptor of descriptors) {
				console.log("Descriptor :")
				console.dir(descriptor, { depth: null })
				const conformingVcList = []
				for (const vc of vcList) {
					// if this vc format is not supported by the verifier, then skip this vc
					if (!Object.keys(presentation_definition.format).includes(vc.format)) {
						continue;
					}

					if (Verify.verifyVcJwtWithDescriptor(descriptor, vc.credential)) {
						conformingVcList.push(vc.credentialIdentifier);
					}
				}
				if (conformingVcList.length == 0) {
					return Err(HandleOutboundRequestError.INSUFFICIENT_CREDENTIALS);
				}
				const requestedFieldNames = descriptor.constraints.fields
					.map((field) => field.path)
					.reduce((accumulator, currentValue) => [...accumulator, ...currentValue])
					.map((field) => field.split('.')[field.split('.').length - 1]);
				mapping.set(descriptor.id, { credentials: [ ...conformingVcList ], requestedFields: requestedFieldNames });
			}
			console.log("Mapping1 = ", mapping)
			console.log("Redirect uri = ", response_uri)
			const verifierDomainName = new URL(response_uri).hostname;
			console.log("Verifier domain = ", verifierDomainName)
			if (mapping.size == 0) {
				console.log("Credentials don't satisfy any descriptor")
				throw new Error("Credentials don't satisfy any descriptor");
			}
			console.log("Mapping = ", mapping)
			return Ok({ conformantCredentialsMap: mapping, verifierDomainName: verifierDomainName })
		}
		catch(error) {
			throw new Error(`Error verifying credentials meeting requirements from input_descriptors: ${error}`)
		}
	}


	/**
	* selection: (key: descriptor_id, value: credentialIdentifier from VerifiableCredential DB entity)
	*/
	private async generateVerifiablePresentation(selection: Map<string, string>, presentation_definition: PresentationDefinition, userId: UserId): Promise<Result<string, WalletKeystoreRequest>> {

		const hasherAndAlgorithm: HasherAndAlgorithm = {
			hasher: (input: string) => createHash('sha256').update(input).digest(),
			algorithm: HasherAlgorithm.Sha256
		}

		/**
		*
		* @param paths example: [ '$.credentialSubject.image', '$.credentialSubject.grade', '$.credentialSubject.val.x' ]
		* @returns example: { credentialSubject: { image: true, grade: true, val: { x: true } } }
		*/
		const generatePresentationFrameForPaths = (paths) => {
			const result = {};

			paths.forEach((path) => {
				const keys = path.split(".").slice(1); // Splitting and removing the initial '$'
				let nestedObj = result;

				keys.forEach((key, index) => {
					if (index === keys.length - 1) {
						nestedObj[key] = true; // Setting the innermost key to true
					}
					else {
						nestedObj[key] = nestedObj[key] || {}; // Creating nested object if not exists
						nestedObj = nestedObj[key]; // Moving to the next nested object
					}
				});
			});
			return result;
		};
		const user = (await getUser(userId)).unwrap();
		let vcListRes = await getAllVerifiableCredentials(user.did);
		if (vcListRes.err) {
			throw "Failed to fetch credentials";
		}
		const allSelectedCredentialIdentifiers = Array.from(selection.values());

		const filteredVCEntities = vcListRes
		.unwrap()
		.filter((vc) =>
			allSelectedCredentialIdentifiers.includes(vc.credentialIdentifier),
		);

		let selectedVCs = [];
		for (const [descriptor_id, credentialIdentifier] of selection) {
			const vcEntity = filteredVCEntities.filter((vc) => vc.credentialIdentifier == credentialIdentifier)[0];
			if (vcEntity.format == "vc+sd-jwt") {
				const descriptor = presentation_definition.input_descriptors.filter((desc) => desc.id == descriptor_id)[0];
				const allPaths = descriptor.constraints.fields
					.map((field) => field.path)
					.reduce((accumulator, currentValue) => [...accumulator, ...currentValue]);
				let presentationFrame = generatePresentationFrameForPaths(allPaths);
				presentationFrame = { vc: presentationFrame }
				const sdJwt = SdJwt.fromCompact<Record<string, unknown>, any>(
					vcEntity.credential
				).withHasher(hasherAndAlgorithm)
				console.log(sdJwt);
				const presentation = await sdJwt.present(presentationFrame);
				selectedVCs.push(presentation);
			}
			else {
				selectedVCs.push(vcEntity.credential);
			}

		}

		const fetchedState = this.states.get(userId.id);
		console.log(fetchedState);
		const { audience, nonce } = fetchedState;


		const result = await this.walletKeystoreManagerService.signJwtPresentation(userId, nonce, audience, selectedVCs);
		if (!result.ok) {
			return Err({
				action: SignatureAction.signJwtPresentation,
				nonce,
				audience,
				verifiableCredentials: selectedVCs,
			});
		}

		return Ok(result.val.vpjwt);
	}

	private async generateAuthorizationResponse(userId: UserId, selection: Map<string, string>): Promise<Result<{ redirect_to?: string }, WalletKeystoreRequest>> {
		console.log("generateAuthorizationResponse userId = ", userId)
		const allSelectedCredentialIdentifiers = Array.from(selection.values());

		const { did } = (await getUser(userId)).unwrap();
		console.log("Verifiable credentials map = ", selection)
		const user = (await getUser(userId)).unwrap();
		let vcListRes = await getAllVerifiableCredentials(user.did);
		if (vcListRes.err) {
			throw "Failed to fetch credentials"
		}
		const filteredVCEntities = vcListRes.unwrap()
			.filter((vc) =>
				allSelectedCredentialIdentifiers.includes(vc.credentialIdentifier)
			);

		try {
			const fetchedState = this.states.get(userId.id);
			const vp_token_result = await this.generateVerifiablePresentation(selection, fetchedState.presentation_definition, userId);
			if (vp_token_result.err) {
				return Err(vp_token_result.val);
			}

			const vp_token: string = vp_token_result.val as string;
			const {presentation_definition, response_uri, state} = this.states.get(userId.id);
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
				// presentation_submission: encodeURI(JSON.stringify(presentationSubmission)),
				presentation_submission: JSON.stringify(presentationSubmission),
				state: state
			};
			const { newLocation } = await axios.post(response_uri, qs.stringify(directPostPayload), {
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

			const verificationState = this.states.get(userId.id);
			if (verificationState && verificationState.camera_was_used) {
				return Ok({ })
			}
			return Ok({ redirect_to: newLocation });
		}
		catch(error) {
			throw new Error(`Error generating Verifiable Presentation: ${error}`);
		}
	}

}


import express, { Router } from 'express';
import { AuthMiddleware } from '../middlewares/auth.middleware';
import _ from 'lodash';
import { appContainer } from '../services/inversify.config';
import { HandleOutboundRequestError, IssuanceErr, OpenidCredentialReceiving, OutboundCommunication } from '../services/interfaces';
import { TYPES } from '../services/types';
import * as z from 'zod';

const openidForCredentialIssuanceService = appContainer.get<OpenidCredentialReceiving>(TYPES.OpenidForCredentialIssuanceService);
const openidForPresentationService = appContainer.get<OutboundCommunication>(TYPES.OpenidForPresentationService);

const communicationHandlerRouter: Router = express.Router();
communicationHandlerRouter.use(AuthMiddleware);

const generateAuthorizationRequestSchema = z.object({
	legal_person_did: z.string()
});

const generateAuthorizationRequestSchemaWithOffer = z.object({
	url: z.string()
});

const handleAuthorizationResponseSchema = z.object({
	url: z.string()
});

const requestCredentialsWithPreAuthorizedSchema = z.object({
	user_pin: z.string()
});

const handleSIOPRequestSchema = z.object({
	url: z.string(),
	camera_was_used: z.boolean()
});

const generateSIOPResponseSchema = z.object({
	verifiable_credentials_map: z.object({})
});

communicationHandlerRouter.post('/handle', async (req, res) => {

	const generateAuthorizationRequestSchemaResult = generateAuthorizationRequestSchema.safeParse(req.body);
	if (generateAuthorizationRequestSchemaResult.success) {
		try {
			const { legal_person_did } = req.body;
			const result = await openidForCredentialIssuanceService.generateAuthorizationRequestURL(req.user.did, null, legal_person_did);
			console.log("Succesfully handled by generateAuthorizationRequestURL");
			return res.send(result);
		}
		catch (err) { console.log(err) }
	}

	const generateAuthorizationRequestWithOfferResult = generateAuthorizationRequestSchemaWithOffer.safeParse(req.body);
	if (generateAuthorizationRequestWithOfferResult.success) {
		try {
			const {
				url,
			} = req.body;
			const result = await openidForCredentialIssuanceService.generateAuthorizationRequestURL(req.user.did, url, null);
			console.log("Successfully handled by generateAuthorizationRequestURL");
			return res.send(result);
		}
		catch (err) { console.log(JSON.stringify(err)) }
	}

	const handleAuthorizationResponseSchemaResult = handleAuthorizationResponseSchema.safeParse(req.body);
	if (handleAuthorizationResponseSchemaResult.success) {
		try {
			const {
				url,
			} = req.body;
	
			if (!(new URL(url).searchParams.get("code"))) {
				throw new Error("No code was provided");
			}
			const result = await openidForCredentialIssuanceService.handleAuthorizationResponse(req.user.did, url);
			if (result.ok) {
				console.log("Successfully handled by handleAuthorizationResponse");
				return res.send({});
			}
		}
		catch (err) { console.log(JSON.stringify(err)) }
	}

	const requestCredentialsWithPreAuthorizedSchemaResult = requestCredentialsWithPreAuthorizedSchema.safeParse(req.body);
	if (requestCredentialsWithPreAuthorizedSchemaResult.success) {
		try {
			const {
				user_pin
			} = req.body;
	
			const response = await openidForCredentialIssuanceService.requestCredentialsWithPreAuthorizedGrant(req.user.did, user_pin);
			console.log("Response = ", response)
			if (response.error) {
				return res.status(401).send({ error: response.error });
			}
			console.log("Successfully handled by requestCredentialsWithPreAuthorizedGrant");
			return res.send(response);
		}
		catch (err) { console.log(JSON.stringify(err)) }
	}

	const handleSIOPRequestResult = handleSIOPRequestSchema.safeParse(req.body);
	if (handleSIOPRequestResult.success) {
		const { url, camera_was_used } = handleSIOPRequestResult.data;
		try {
			const outboundRequestResult = await openidForPresentationService.handleRequest(req.user.did, url, camera_was_used);
			if (!outboundRequestResult.ok) {
				if (outboundRequestResult.val == HandleOutboundRequestError.INSUFFICIENT_CREDENTIALS) {
					return res.send({ error: HandleOutboundRequestError.INSUFFICIENT_CREDENTIALS });
				}
				throw new Error("Failed to handle outbound request")
			}
			const outboundRequest = outboundRequestResult.val;
			console.log("Outbound request = ", outboundRequest)
			if (outboundRequest.conformantCredentialsMap && outboundRequest.verifierDomainName) {
				const { conformantCredentialsMap, verifierDomainName } = outboundRequest;
				// convert from map to JSON
				const mapArray = Array.from(conformantCredentialsMap);
				const conformantCredentialsMapJSON = Object.fromEntries(mapArray);
				console.log("Successfully handled by handleRequest");
				return res.send({ conformantCredentialsMap: conformantCredentialsMapJSON, verifierDomainName });
			}
			else if (outboundRequest.redirect_to) {
				console.log("Successfully handled by handleRequest");
				return res.send({ redirect_to: outboundRequest.redirect_to });
			}
			else {
				const errText = `Error parsing authorization request: Outbound request error`;
				throw new Error(errText)
			}
		}
		catch (err) { console.log(JSON.stringify(err)) }
	}

	const generateSIOPResponseSchemaResult = generateSIOPResponseSchema.safeParse(req.body);
	if (generateSIOPResponseSchemaResult.success) {
		const {
			verifiable_credentials_map, // { "descriptor_id1": "urn:vid:123", "descriptor_id1": "urn:vid:645" }
		} = req.body;
	
		console.log("Credentials map = ", verifiable_credentials_map)
		const selection = new Map(Object.entries(verifiable_credentials_map)) as Map<string, string>;
		console.log("Selection = ", verifiable_credentials_map)
		try {
			const result = await openidForPresentationService.sendResponse(req.user.did, selection);
	
			if (!result.ok) {
				throw new Error("send SIOP response returned error")
			}
	
			const { redirect_to, error } = result.val;
			if (error) {
				const errText = `Error generating authorization response: ${error}`;
				console.error(errText);
				throw new Error(errText);
			}
			console.log("Successfully handled by sendResponse");
			return res.send({ redirect_to });
		}
		catch(error) {
			const errText = `Error generating authorization response: ${error}`;
			console.log(errText);
		}	
	}
	return res.status(400).send({ error: "Could not handle" });
});

export {
	communicationHandlerRouter
}

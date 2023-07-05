import express, { Router } from 'express';
import { AuthMiddleware } from '../middlewares/auth.middleware';
import { appContainer } from '../services/inversify.config';
import { TYPES } from '../services/types';
import { OutboundCommunication } from '../services/interfaces';

const openidForPresentationService = appContainer.get<OutboundCommunication>(TYPES.OpenidForPresentationService);




/**
 * "/presentation"
 * This controller will be used on the presentation phase
 */
const presentationRouter: Router = express.Router();
presentationRouter.use(AuthMiddleware);



presentationRouter.post('/handle/authorization/request', async (req, res) => {
	const {
		authorization_request
	} = req.body;

	try{
		const outboundRequest = await openidForPresentationService.handleRequest(req.user.username, authorization_request)
		if (outboundRequest.conformantCredentialsMap && outboundRequest.verifierDomainName) {
			const { conformantCredentialsMap, verifierDomainName } = outboundRequest;
			// convert from map to JSON
			const mapArray = Array.from(conformantCredentialsMap);
			const conformantCredentialsMapJSON = Object.fromEntries(mapArray);
			return res.send({ conformantCredentialsMap: conformantCredentialsMapJSON, verifierDomainName });
		}
		else if (outboundRequest.redirect_to) {
			return res.send({ redirect_to: outboundRequest. redirect_to });
		}
		else {
			const errText = `Error parsing authorization request: Outbound request error`;
			return res.status(500).send({error: errText});
		}

	}
	catch(error) {
		const errText = `Error parsing authorization request: ${error}`;
		return res.status(500).send({error: errText});
	}
})

presentationRouter.post('/generate/authorization/response', async (req, res) => {
	const {
		verifiable_credentials_map // { "descriptor_id1": "urn:vid:123", "descriptor_id1": "urn:vid:645" }
	} = req.body;

	const selection = new Map(Object.entries(verifiable_credentials_map)) as Map<string, string>;
	try {
		const { redirect_to, error } = await openidForPresentationService.sendResponse(req.user.username, selection);
		if (error) {
			const errText = `Error generating authorization response: ${error}`;
			console.error(errText);
			return res.status(500).send({error: errText});
		}
		return res.send({ redirect_to });
	}
	catch(error) {
		const errText = `Error generating authorization response: ${error}`;
		console.error(errText);
		return res.status(500).send({error: errText});
	}
})




export {
	presentationRouter
}
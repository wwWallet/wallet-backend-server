
import express, { Router } from 'express';
import { AuthMiddleware } from '../middlewares/auth.middleware';
import _ from 'lodash';
import { appContainer } from '../services/inversify.config';
import { IssuanceErr, OpenidCredentialReceiving } from '../services/interfaces';
import { TYPES } from '../services/types';


const openidForCredentialIssuanceService = appContainer.get<OpenidCredentialReceiving>(TYPES.OpenidForCredentialIssuanceService);

/**
 * "/issuance"
 * This controller will be used on the issuance phase
 */
const issuanceRouter: Router = express.Router();
issuanceRouter.use(AuthMiddleware);


issuanceRouter.post('/generate/authorization/request', async (req, res) => {
	console.info("Received initiation")
	try {
		const {
			legal_person_did,
		} = req.body;
		const result = await openidForCredentialIssuanceService.generateAuthorizationRequestURL(req.user.did, null, legal_person_did);
		res.send(result);
	}
	catch(err) {
		res.status(500).send({});
	}

})

issuanceRouter.post('/generate/authorization/request/with/offer', async (req, res) => {
	try {
		const {
			credential_offer_url,
		} = req.body;

		const result = await openidForCredentialIssuanceService.generateAuthorizationRequestURL(req.user.did, credential_offer_url, null);
		res.send(result);
	}
	catch(err) {
		return res.status(500).send({});
	}

})

issuanceRouter.post('/handle/authorization/response', async (req, res) => {
	try {
		const {
			authorization_response_url
		} = req.body;


		if (!(new URL(authorization_response_url).searchParams.get("code"))) {
			return res.status(500).send({});
		}
		const result = await openidForCredentialIssuanceService.handleAuthorizationResponse(req.user.did, authorization_response_url);
		if (result.ok) {
			res.send({});
		} else if (result.val === IssuanceErr.STATE_NOT_FOUND) {
			res.status(404).send({});
		} else {
			res.status(500).send({});
		}
	}
	catch(err) {
		res.status(500).send({ error: "Failed to handle authorization response" });
	}

})

issuanceRouter.post('/request/credentials/with/pre_authorized', async (req, res) => {
	try {
		const {
			user_pin
		} = req.body;

		await openidForCredentialIssuanceService.requestCredentialsWithPreAuthorizedGrant(req.user.did, user_pin);
		res.send({});
	}
	catch(err) {
		res.status(500).send({ error: "Failed to handle authorization response" });
	}

})

export {
	issuanceRouter
}

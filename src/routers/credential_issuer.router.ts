import { Router } from "express";
import { Ok } from "ts-results";
import { getAllCredentialIssuers } from "../entities/CredentialIssuer.entity";
import { getAllCredentialPortals } from "../entities/CredentialPortal.entity";


const credentialIssuerRouter = Router();


credentialIssuerRouter.get('/all', async (req, res) => {
	const issuerResult = await getAllCredentialIssuers();

	if (issuerResult.err) {
		return res.status(400).send({ error: "Error fetching credential issuers"});
	}

	const portalResult = await getAllCredentialPortals();

	if (portalResult.err) {
		return res.status(400).send({ error: "Error fetching credential portals"});
	}

	const result = Ok({
		issuers: issuerResult.val,
		portals: portalResult.val,
	});

	res.send(result.val);
})

credentialIssuerRouter.get('/all-issuers', async (req, res) => {
	const result = await getAllCredentialIssuers();

	if (result.err) {
		return res.status(400).send({ error: "Error fetching credential issuers"});
	}

	res.send(result.val);
})

credentialIssuerRouter.get('/all-portals', async (req, res) => {
	const result = await getAllCredentialPortals();

	if (result.err) {
		return res.status(400).send({ error: "Error fetching credential portals"});
	}

	res.send(result.val);
})

export {
	credentialIssuerRouter
}

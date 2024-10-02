import { Router } from "express";
import { getAllCredentialIssuers } from "../entities/CredentialIssuer.entity";


const credentialIssuerRouter = Router();


credentialIssuerRouter.get('/all', async (req, res) => {
	const result = await getAllCredentialIssuers();

	if (result.err) {
		return res.status(400).send({ error: "Error fetchig credential issuers"});
	}

	res.send(result.val);
})


export {
	credentialIssuerRouter
}

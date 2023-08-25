import { Router } from "express";
import { getAllLegalPersons } from "../entities/LegalPerson.entity";



const legalPersonRouter = Router();

legalPersonRouter.get('/issuers/all', async (req, res) => {
	try {
		const lps = (await getAllLegalPersons()).unwrap();
		return res.send(lps);
	}
	catch(e) {
		return res.status(400).send({ error: "Failed to get legal persons", error_description: e });
	}
})

export { legalPersonRouter };
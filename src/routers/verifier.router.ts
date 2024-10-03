import { Router } from "express";
import { getAllVerifiers } from "../entities/Verifier.entity";


const verifierRouter = Router();


verifierRouter.get('/all', async (req, res) => {
	const result = await getAllVerifiers();

	if (result.err) {
		return res.status(400).send({ error: "Error fetching verifiers"});
	}

	res.send(result.val);
})


export {
	verifierRouter
}

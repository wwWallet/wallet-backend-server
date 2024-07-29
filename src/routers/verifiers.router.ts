import { Router } from "express";
import { appContainer } from "../services/inversify.config";
import { VerifierRegistryService } from "../services/VerifierRegistryService";



const verifiersRouter = Router();
const verifiersRegistryService = appContainer.resolve(VerifierRegistryService)


verifiersRouter.get('/all', async (req, res) => {
	res.send({ verifiers: await verifiersRegistryService.getAllVerifiers() });
});

export default verifiersRouter;

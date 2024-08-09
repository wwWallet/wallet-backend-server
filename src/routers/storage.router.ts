import express, { Request, Response, Router } from "express";
import { getAllVerifiableCredentials, getVerifiableCredentialByCredentialIdentifier, deleteVerifiableCredential } from "../entities/VerifiableCredential.entity";
import { getAllVerifiablePresentations, getPresentationByIdentifier } from "../entities/VerifiablePresentation.entity";



const storageRouter: Router = express.Router();


storageRouter.get('/vc', getAllVerifiableCredentialsController);
storageRouter.get('/vc/:credential_identifier', getVerifiableCredentialByCredentialIdentifierController);
storageRouter.delete('/vc/:credential_identifier', deleteVerifiableCredentialController);
storageRouter.get('/vp', getAllVerifiablePresentationsController);
storageRouter.get('/vp/:presentation_identifier', getPresentationByPresentationIdentifierController);


async function getAllVerifiableCredentialsController(req: Request, res: Response) {
	const holderDID = req.user.did;
	console.log("Holder did", holderDID)
	const vcListResult = await getAllVerifiableCredentials(holderDID);
	if (vcListResult.err) {
		res.status(500).send({});
		return;
	}
	const vc_list = vcListResult.unwrap()
	.map((v) => {
		return {
			...v,
			issuanceDate: Math.floor(v.issuanceDate.getTime() / 1000)
		}
	});

	res.status(200).send({ vc_list: vc_list })

}

async function getVerifiableCredentialByCredentialIdentifierController(req: Request, res: Response) {
	const holderDID = req.user.did;
	const { credential_identifier } = req.params;
	const vcFetchResult = await getVerifiableCredentialByCredentialIdentifier(holderDID, credential_identifier);
	if (vcFetchResult.err) {
		return res.status(500).send({ error: vcFetchResult.val })
	}
	const vc = vcFetchResult.unwrap();
	const changedVC = { ...vc, issuanceDate: Math.floor(vc.issuanceDate.getTime() / 1000)}
	res.status(200).send(vc);
}

async function deleteVerifiableCredentialController(req: Request, res: Response) {
	const holderDID = req.user.did;
	const { credential_identifier } = req.params;
	const deleteResult = await deleteVerifiableCredential(holderDID, credential_identifier);
	if (deleteResult.err) {
		return res.status(500).send({ error: deleteResult.val });
	}
	res.status(200).send({ message: "Verifiable Credential deleted successfully." });
}



async function getAllVerifiablePresentationsController(req: Request, res: Response) {
	const holderDID = req.user.did;
	const vpListResult = await getAllVerifiablePresentations(holderDID);
	if (vpListResult.err) {
		res.status(500).send({});
		return;
	}
	const vp_list = vpListResult.unwrap()
	.map((v) => {
		return {
			...v,
			issuanceDate: Math.floor(v.issuanceDate.getTime() / 1000)
		}
	});
	res.status(200).send({ vp_list: vp_list })
}

async function getPresentationByPresentationIdentifierController(req: Request, res: Response) {
	const holderDID = req.user.did;
	const { presentation_identifier } = req.params;

	const vpResult = await getPresentationByIdentifier(holderDID, presentation_identifier);
	if (vpResult.err) {
		return res.status(500).send({ error: vpResult.val })
	}
	const vp = vpResult.unwrap();
	const changedVC = { ...vp, issuanceDate: Math.floor(vp.issuanceDate.getTime() / 1000)}
	res.status(200).send(vp);
}


export {
	storageRouter
}

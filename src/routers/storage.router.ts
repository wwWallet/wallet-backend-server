import express, { Router } from "express";
import { getAllVerifiableCredentials, getVerifiableCredentialByCredentialIdentifier } from "../entities/VerifiableCredential.entity";
import { getAllVerifiablePresentations, getPresentationByIdentifier } from "../entities/VerifiablePresentation.entity";



const storageRouter: Router = express.Router();


storageRouter.get('/vc', getAllVerifiableCredentialsController);
storageRouter.get('/vc/:credential_identifier', getVerifiableCredentialByCredentialIdentifierController);
storageRouter.get('/vp', getAllVerifiablePresentationsController);
storageRouter.get('/vp/:presentation_identifier', getPresentationByPresentationIdentifierController);


async function getAllVerifiableCredentialsController(req, res) {
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

async function getVerifiableCredentialByCredentialIdentifierController(req, res) {
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




async function getAllVerifiablePresentationsController(req, res) {
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

async function getPresentationByPresentationIdentifierController(req, res) {
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

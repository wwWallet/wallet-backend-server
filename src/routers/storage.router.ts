import express, { Request, Response, Router } from "express";
import { getAllVerifiableCredentials, getVerifiableCredentialByCredentialIdentifier, deleteVerifiableCredential, createVerifiableCredential } from "../entities/VerifiableCredential.entity";
import { createVerifiablePresentation, deletePresentationsByCredentialId, getAllVerifiablePresentations, getPresentationByIdentifier } from "../entities/VerifiablePresentation.entity";
import { sendPushNotification } from "../lib/firebase";
import { getUser } from "../entities/user.entity";


const storageRouter: Router = express.Router();

storageRouter.post('/vc', storeCredential);
storageRouter.get('/vc', getAllVerifiableCredentialsController);
storageRouter.get('/vc/:credential_identifier', getVerifiableCredentialByCredentialIdentifierController);
storageRouter.delete('/vc/:credential_identifier', deleteVerifiableCredentialController);
storageRouter.post('/vp', storeVerifiablePresentation);
storageRouter.get('/vp', getAllVerifiablePresentationsController);
storageRouter.get('/vp/:presentation_identifier', getPresentationByPresentationIdentifierController);


async function storeCredential(req: Request, res: Response) {
	createVerifiableCredential({
		holderDID: req.user.did,
		issuanceDate: new Date(),
		...req.body,
	}).then(async () => {
		// inform all installed instances of the wallet that a credential has been received

		const u = await getUser(req.user.id);
		if (u.err) {
			return res.send({});
		}

		const user = u.unwrap();
		if (user.fcmTokenList) {
			for (const fcmToken of user.fcmTokenList) {
				sendPushNotification(fcmToken.value, "New Credential", "A new verifiable credential is in your wallet").catch(err => {
					console.log("Failed to send notification")
					console.log(err)
				});
			}
		}
	})
	res.send({});
}

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
	res.status(200).send(vc);
}

async function deleteVerifiableCredentialController(req: Request, res: Response) {
	const holderDID = req.user.did;
	const { credential_identifier } = req.params;
	await deletePresentationsByCredentialId(holderDID, credential_identifier)
	const deleteResult = await deleteVerifiableCredential(holderDID, credential_identifier);
	if (deleteResult.err) {
		return res.status(500).send({ error: deleteResult.val });
	}
	res.status(200).send({ message: "Verifiable Credential deleted successfully." });
}


async function storeVerifiablePresentation(req, res) {
	const holderDID = req.user.did;
	const storableVerifiablePresentation = req.body;
	await createVerifiablePresentation({
		...storableVerifiablePresentation,
		holderDID,
	});

	res.send({});
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
	res.status(200).send(vp);
}


export {
	storageRouter
}

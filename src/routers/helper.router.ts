import axios from "axios";
import { Router } from "express";
import https from 'https';


const helperRouter = Router()

const agent = new https.Agent({
	// rejectUnauthorized: false, // Accept self-signed certificates for testing purposes
});


helperRouter.post('/get-cert', async (req, res) => {
	axios.get(req.body.url, { httpsAgent: agent }).then((response) => {
		const socket = response.request.socket; // Access the underlying socket
		const certificate = socket.getPeerCertificate(true); // Get full certificate chain

		if (certificate) {
			console.log("parsing cert...")
			console.log('Subject:', certificate.subject);
			console.log('Issuer:', certificate.issuer);
			let cert = certificate;
			let certChainPEM = [];
			const x5c = [];
			while (cert) {
				const pemCert = `-----BEGIN CERTIFICATE-----\n${cert.raw.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
				certChainPEM.push(pemCert);
				x5c.push(cert.raw.toString('base64'));
				cert = cert.issuerCertificate === cert ? null : cert.issuerCertificate;
			}
			return res.status(200).send({ x5c });
		}
		return res.status(400).send({ error: "INVALID_CERT" });

	}).catch((error) => {
		console.error('Error fetching certificate:', error);
		return res.status(400).send({ error: "INVALID_CERT" });
	});
})

export {
	helperRouter
}
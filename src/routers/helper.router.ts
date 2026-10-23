import axios from "axios";
import { Router } from "express";
import https from 'https';
import { getAllTrustedRootCertificates } from "../entities/TrustedRootCertificate.entity";
import { config } from "../../config";
import { logger } from "../logger";

const log = logger.child({ module: "Helper" });

const helperRouter = Router()

const agent = new https.Agent({
	rejectUnauthorized: !config.debugAcceptUnauthorizedHttps
});

helperRouter.all('/auth-check', (req, res) => {
	log.info("Auth from Relay: OK");
	return res.status(200).send();
})

helperRouter.post('/get-cert', async (req, res) => {
	// Stream the response so it resolves on headers, while the TLS socket is still open
	axios.get(req.body.url, { httpsAgent: agent, responseType: 'stream' }).then((response) => {
		const socket = response.request.socket; // Access the underlying socket
		const certificate = socket.getPeerCertificate(true); // Get full certificate chain
		response.data.destroy(); // The body itself is not needed

		if (certificate) {
			log.info("parsing cert...");
			log.info({ subject: certificate.subject, issuer: certificate.issuer }, 'Fetched certificate');
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
		log.error({ err: error }, 'Error fetching certificate');
		return res.status(400).send({ error: "INVALID_CERT" });
	});
})

helperRouter.get('/iaca-list', async (req, res) => {
	const certs = await getAllTrustedRootCertificates();
	if (certs.ok) {
		return res.send({ iaca_list: certs.val });
	}
	return res.status(500).send({ error: certs.val });
});

export {
	helperRouter
}

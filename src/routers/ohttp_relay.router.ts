import express, { Router } from 'express';
import fetch from 'node-fetch';
import { config } from '../../config';
import { logger } from '../logger';

const log = logger.child({ module: 'OhttpRelay' });

const ohttpRelayRouter: Router = Router();

const relayTargetUrl = new URL('gateway', config.ohttpGatewayUrl.endsWith('/') ? config.ohttpGatewayUrl : `${config.ohttpGatewayUrl}/`).toString();

ohttpRelayRouter.post('/', express.raw({ type: '*/*', limit: '17mb' }), async (req, res) => {
	try {
		const requestBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from([]);
		const requestHeaders: Record<string, string> = {
			'User-Agent': 'relay/1.0',
		};

		if (typeof req.headers['content-type'] === 'string') {
			requestHeaders['Content-Type'] = req.headers['content-type'];
		}

		if (typeof req.headers.accept === 'string') {
			requestHeaders.Accept = req.headers.accept;
		}

		const gatewayResponse = await fetch(relayTargetUrl, {
			method: 'POST',
			body: requestBody,
			headers: requestHeaders,
			redirect: 'manual',
		});

		res.status(gatewayResponse.status);
		gatewayResponse.headers.forEach((value, key) => {
			if (key.toLowerCase() === 'transfer-encoding' || key.toLowerCase() === 'connection') {
				return;
			}
			res.setHeader(key, value);
		});

		const responseBody = Buffer.from(await gatewayResponse.arrayBuffer());
		return res.send(responseBody);
	}
	catch (error) {
		log.error({ err: error }, 'OHTTP relay proxy error');
		return res.status(502).send();
	}
});

export {
	ohttpRelayRouter
};

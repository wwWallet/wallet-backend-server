import axios from 'axios';
import express, { Request, Response, Router } from 'express';
const proxyRouter: Router = express.Router();

proxyRouter.post('/', async (req, res) => {
	const { headers, method, url, data } = req.body;
	try {
		console.log("URL = ", url)
		const response = await axios({
			url: url,
			headers: headers,
			method: method,
			data: data,
			maxRedirects: 0,
		});

		return res.status(200).send({
			status: response.status,
			headers: response.headers,
			data: response.data,
		})
	}
	catch (err) {
		if (err.response && err.response.data) {
			console.error("Error data = ", err.response.data)
		}
		if (err.response && err.response.status == 302) {
			return res.status(200).send({ status: err.response.status, headers: err.response.headers, data: {} })
		}
		return res.status(err.response?.status ?? 104).send({ status: err.response?.status ?? 104, data: err.response?.data, headers: err.response?.headers });
	}
})

export {
	proxyRouter
}

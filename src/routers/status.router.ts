import express, { Request, Response, Router } from 'express';

/**
 * "/status" endpoint that returns 200
 * as a response if the service is working
 */
const statusRouter: Router = express.Router();

statusRouter.get('/', (_req: Request, res: Response) => {
	res.status(200).send({status: 'ok'});
});

export {
	statusRouter
}
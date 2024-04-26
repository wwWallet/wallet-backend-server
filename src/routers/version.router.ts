import express, { Request, Response, Router } from 'express';
import fs from 'fs';
import path from 'path';

const version = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../app/package.json'), 'utf-8').toString()).version;
const versionRouter: Router = express.Router();

versionRouter.get('/version', (_req: Request, res: Response) => {
	res.status(200).send({
		version: version
	});
});

export {
	versionRouter
}

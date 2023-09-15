import express, { Express, Request, Response } from 'express';
import config from '../config';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import userController from './routers/user.router';
import { AuthMiddleware } from './middlewares/auth.middleware';
import { statusRouter } from './routers/status.router';
import { issuanceRouter } from './routers/issuance.router';
import { storageRouter } from './routers/storage.router';
import { presentationRouter } from './routers/presentation.router';
import { legalPersonRouter } from './routers/legal_person.router';
import verifiersRouter from './routers/verifiers.router';
import { reviverTaggedBase64UrlToBuffer } from './util/util';
import * as WebSocket from 'ws';
import http from 'http';
import { appContainer } from './services/inversify.config';
import { SocketManagerServiceInterface } from './services/interfaces';
import { TYPES } from './services/types';
import https from 'https';
import fs from 'fs';
import path from 'path';


const app: Express = express();
// __dirname is "/path/to/dist/src"

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({ reviver: reviverTaggedBase64UrlToBuffer }));

app.use(express.static('public'));
// __dirname is "/path/to/dist/src"
// public is located at "/path/to/dist/src"
app.use(cors({ credentials: true, origin: true }));


// define routes and middleware here
app.use('/status', statusRouter);
app.use('/user', userController);
// app.get('/jwks', async (req, res) => {
// 	const users = await getAllUsers();
// 	if (users.err) {
// 		return res.status(500).send({});
// 	}

// 	const jwksPromises = users.unwrap().map(async (user) => {
// 		const keys = JSON.parse(user.keys);
// 		const w = await NaturalPersonWallet.initializeWallet(keys);
// 		const did = w.key.did
// 		return { ...w.getPublicKey(), kid: did };
// 	})
// 	const jwks = await Promise.all(jwksPromises);
// 	return res.send(jwks);
// })



app.use(AuthMiddleware);

// all the following endpoints are guarded by the AuthMiddleware
app.use('/issuance', issuanceRouter);
app.use('/storage', storageRouter);
app.use('/presentation', presentationRouter);
app.use('/legal_person', legalPersonRouter);
app.use('/verifiers', verifiersRouter);





if (config.ssl == "true") {
	const privateKey = fs.readFileSync(path.join(__dirname, "../../keys/key.pem"), 'utf8');
	const certificate = fs.readFileSync(path.join(__dirname, "../../keys/cert.pem"), 'utf8');
	const passphrase = fs.readFileSync(path.join(__dirname, "../../keys/password.txt"), 'utf8');
	const credentials = { key: privateKey, cert: certificate, passphrase: passphrase };
	const server = https.createServer(credentials, app);

	appContainer.get<SocketManagerServiceInterface>(TYPES.SocketManagerService).register(server);

}
else {
	const server = http.createServer(app);
	appContainer.get<SocketManagerServiceInterface>(TYPES.SocketManagerService).register(server);

	server.listen(config.port, () => {
		console.log(`eDiplomas Register app listening at ${config.url}`)
	});
}


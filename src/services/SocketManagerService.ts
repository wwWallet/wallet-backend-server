import { injectable } from "inversify";
import { ExpectingSocketMessageErr, SocketManagerServiceInterface } from "./interfaces";
import * as WebSocket from 'ws';
import http from 'http';
import { Err, Ok, Result } from "ts-results";
import { ServerSocketMessage, ClientSocketMessage, SignatureAction } from "./shared.types";
import { jwtVerify } from "jose";
import { config } from "../../config";
import { UserId } from "../entities/user.entity";
import { logger } from "../logger";

const log = logger.child({ module: "SocketManager" });

const openSockets = new Map<string, WebSocket.WebSocket>();

const secret = new TextEncoder().encode(config.appSecret);

@injectable()
export class SocketManagerService implements SocketManagerServiceInterface {
	wss: WebSocket.Server;

	constructor() { }

	register(server: http.Server) {
		this.wss = new WebSocket.Server({ server });

		this.wss.on('connection', (ws) => {
			log.info('WebSocket client connected');
			// Handle incoming messages from the WebSocket client
			ws.on('message', async (message) => {
				log.info({ message: message.toString() }, "Received WebSocket message");
				// Parse Handshake Request
				// wait for appToken to authenticate
				try {
					const { appToken } = JSON.parse(message.toString());
					if (!appToken) {
						return;
					}
					const { payload } = await jwtVerify(appToken, secret);
					openSockets.set(payload.uuid as string, ws);
					ws.send(JSON.stringify({ type: "FIN_INIT" }));
					log.info("Handshake established");
				}
				catch(e) {
					log.warn({ err: e }, "Handshake failed");
				}
			});
			ws.on('close', () => {
				log.info('WebSocket closed');
			})
		});
	}

	async send(userId: UserId, message: ServerSocketMessage): Promise<Result<void, void>> {
		const ws = openSockets.get(userId.id);
		ws.send(JSON.stringify(message));
		return Ok.EMPTY;
	}

	async expect(userId: UserId, message_id: string, action: SignatureAction): Promise<Result<{ message: ClientSocketMessage }, ExpectingSocketMessageErr>> {
		const ws = openSockets.get(userId.id);
		return new Promise((resolve, reject) => {
			ws.onmessage = event => {
				try {
					const clientMessage = JSON.parse(event.data.toString()) as ClientSocketMessage;
					if (message_id !== clientMessage.message_id) {
						log.error({ expected: message_id, got: clientMessage.message_id }, "Wrong message id");
						return;
					}
					else if (action !== clientMessage.response.action) {
						return resolve(Err(ExpectingSocketMessageErr.WRONG_ACTION));
					}
					return resolve(Ok({ message: clientMessage }));
				}
				catch(e) {
					resolve(Err(ExpectingSocketMessageErr.FAILED_TO_RECEIVE));
				}
			}
		})

	}



}

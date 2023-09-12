import { injectable } from "inversify";
import { SocketManagerServiceInterface } from "./interfaces";
import { Application } from "express";
import * as WebSocket from 'ws';
import http from 'http';
import { Result } from "ts-results";
import { ServerSocketMessage, ClientSocketMessage } from "./shared.types";


@injectable()
export class SocketManagerService implements SocketManagerServiceInterface {
	wss: WebSocket.Server;

	
	constructor() { }

	register(server: http.Server) {
		this.wss = new WebSocket.Server({ server });

		this.wss.on('connection', (ws) => {
			console.log('WebSocket client connected');
			// Handle incoming messages from the WebSocket client
			ws.on('message', (message) => {
				console.log(`Received: ${message}`);
		
				// Send a response back to the WebSocket client
				ws.send(`You sent: ${message}`);
			});
		
			ws.on('close', () => {
				console.log('closedd----')
			})
		});
	}

	send(userDid: string, message: ServerSocketMessage): Promise<Result<{ message_id: string }, void>> {
		throw new Error("Method not implemented.");
	}
	expect(userDid: string, message_id: string): Promise<Result<{ message: ClientSocketMessage }, void>> {
		throw new Error("Method not implemented.");
	}



}
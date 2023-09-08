import { injectable } from 'inversify';
import 'reflect-metadata';
import { DidKeyUtilityService } from './interfaces';
import { JWK } from 'jose';
import * as ed25519 from "@transmute/did-key-ed25519";
import * as crypto from "node:crypto";
import { WalletKey } from '@gunet/ssi-sdk';


@injectable()
export class W3CDidKeyUtilityService implements DidKeyUtilityService {


	async getPublicKeyJwk(did: string): Promise<JWK> {
		const result = await ed25519.resolve(did, { accept: 'application/did+json' });
		const verificationMethod = result.didDocument.verificationMethod[0] as any;
		return verificationMethod.publicKeyJwk as JWK;
	}

	async generateKeyPair(): Promise<{ did: string, key: any }> {
		const { didDocument, keys } = await ed25519.generate(
			{
				secureRandom: () => {
					return crypto.randomBytes(32);
				},
			},
			{ accept: 'application/did+json' }
		);
		console.log("DID document = ", didDocument)
		console.log("Keys = ", keys);
		const key: WalletKey = {
			privateKey: keys[0].privateKeyJwk,
			publicKey: keys[0].publicKeyJwk,
			alg: 'EdDSA',
			verificationMethod: didDocument.id + '#' + didDocument.id.split(':')[2],
			did: didDocument.id
		};

		return { did: didDocument.id, key: key };
	}
}
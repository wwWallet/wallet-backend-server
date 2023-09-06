import { injectable } from 'inversify';
import 'reflect-metadata';
import { DidKeyUtilityService } from './interfaces';
import { JWK } from 'jose';


@injectable()
export class EBSIDidKeyUtilityService implements DidKeyUtilityService {


	async getPublicKeyJwk(did: string): Promise<JWK> {
		throw new Error("Not implemented");
	}

	async generateKeyPair(): Promise<{ did: string, key: any }> {
		throw new Error("Not implemented")
	}
}
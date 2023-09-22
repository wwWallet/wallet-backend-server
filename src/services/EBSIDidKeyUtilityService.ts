import { injectable } from 'inversify';
import 'reflect-metadata';
import { DidKeyUtilityService } from './interfaces';
import { JWK } from 'jose';
import config from '../../config';
import { NaturalPersonWallet, WalletKey, getPublicKeyFromDid } from '@gunet/ssi-sdk';


@injectable()
export class EBSIDidKeyUtilityService implements DidKeyUtilityService {


	async getPublicKeyJwk(did: string): Promise<JWK> {
		return await getPublicKeyFromDid(did);
	}

	async generateKeyPair(): Promise<{ did: string, key: WalletKey }> {
		const naturalPersonWallet: NaturalPersonWallet = await new NaturalPersonWallet().createWallet(config.alg);
		return { did: naturalPersonWallet.key.did, key: naturalPersonWallet.key };
	}
}
import path from 'node:path';
import fs from 'node:fs';
import { parse } from 'yaml';

const yamlConfig = fs.readFileSync(path.join(process.cwd(), 'config.yml')).toString()

console.log(parse(yamlConfig));

export const config: {
	url: string;
	port: string;
	appSecret: string;
	ssl: string;
	db: {
		host: string;
		port: string;
		username: string;
		password: string;
		dbname: string;
	}
	walletClientUrl: string;
	webauthn: {
		attestation: string;
		origin: string;
		rp: {
			id: string;
			name: string;
		}
	}
	alg: string;
	notifications: {
		enabled: string;
		serviceAccount: string;
	}
}= parse(yamlConfig).backend

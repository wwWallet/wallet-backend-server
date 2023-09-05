import { injectable } from "inversify";
import 'reflect-metadata';

type Verifier = {
	id: number;
	name: string;
	url: string;
	scopes: {
		name: string;
		description: string;
	}[];
}

@injectable()
export class VerifierRegistryService {
	private readonly verifierRegistry: Verifier[] = [
		{
			id: 1,
			name: "National Authority",
			url: "http://wallet-enterprise-vid-issuer:8003/verification/authorize",
			scopes: [
				{
					name: "vid",
					description: "Present your Verifiable ID"
				},
				{
					name: "ver:test",
					description: "Test"
				}
			]
		}
	];



	async getAllVerifiers() {
		return this.verifierRegistry;
	}
}
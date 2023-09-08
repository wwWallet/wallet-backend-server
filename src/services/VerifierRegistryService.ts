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
			name: "ACME verifier",
			url: "http://wallet-enterprise-acme-verifier:8005/verification/authorize",
			scopes: [
				{
					name: "vid",
					description: "Present your Verifiable ID"
				},
				{
					name: "diploma",
					description: "Present your Diploma"
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
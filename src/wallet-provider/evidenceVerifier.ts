import fetch from "node-fetch";
import { z } from "zod";
import { PublicJwk, VerifiedKeyEvidence } from "./keyAttestation";

const evidenceReferenceSchema = z.string().min(1).max(255);
const assuranceValueSchema = z.string().min(1).max(128);

const activationVerificationResponseSchema = z.object({
	verified: z.literal(true),
	evidence_reference: evidenceReferenceSchema,
});

const keyVerificationResponseSchema = activationVerificationResponseSchema.extend({
	key_storage: z.array(assuranceValueSchema).min(1),
	user_authentication: z.array(assuranceValueSchema).min(1),
	certification: z.string().url().max(2048),
});

export type ActivationEvidenceResult = {
	evidenceReference: string;
};

export interface WalletProviderEvidenceVerifier {
	verifyActivation(input: {
		walletInstanceId: string;
		userId: string;
		walletName: string;
		walletVersion: string;
		evidence: unknown;
	}): Promise<ActivationEvidenceResult>;

	verifyKeys(input: {
		walletInstanceId: string;
		userId: string;
		activationEvidenceReference: string;
		jwks: PublicJwk[];
		thumbprints: string[];
		evidence: unknown;
	}): Promise<VerifiedKeyEvidence>;
}

export class EvidenceRejectedError extends Error { }
export class EvidenceVerifierUnavailableError extends Error { }

export class RemoteWalletProviderEvidenceVerifier implements WalletProviderEvidenceVerifier {
	constructor(
		private readonly endpoint: string,
		private readonly bearerToken?: string,
		private readonly timeoutMilliseconds: number = 5000,
	) { }

	async verifyActivation(input: {
		walletInstanceId: string;
		userId: string;
		walletName: string;
		walletVersion: string;
		evidence: unknown;
	}): Promise<ActivationEvidenceResult> {
		const response = await this.request({
			type: "wallet_instance_activation",
			wallet_instance_id: input.walletInstanceId,
			user_id: input.userId,
			wallet_name: input.walletName,
			wallet_version: input.walletVersion,
			evidence: input.evidence,
		});
		if (isRejectedResponse(response)) {
			throw new EvidenceRejectedError("Wallet integrity evidence was rejected");
		}
		const parsed = activationVerificationResponseSchema.safeParse(response);
		if (!parsed.success) {
			throw new EvidenceVerifierUnavailableError("The evidence verifier returned an invalid activation response");
		}
		return { evidenceReference: parsed.data.evidence_reference };
	}

	async verifyKeys(input: {
		walletInstanceId: string;
		userId: string;
		activationEvidenceReference: string;
		jwks: PublicJwk[];
		thumbprints: string[];
		evidence: unknown;
	}): Promise<VerifiedKeyEvidence> {
		const response = await this.request({
			type: "key_attestation",
			wallet_instance_id: input.walletInstanceId,
			user_id: input.userId,
			activation_evidence_reference: input.activationEvidenceReference,
			attested_keys: input.jwks,
			attested_key_thumbprints: input.thumbprints,
			evidence: input.evidence,
		});
		if (isRejectedResponse(response)) {
			throw new EvidenceRejectedError("Key integrity evidence was rejected");
		}
		const parsed = keyVerificationResponseSchema.safeParse(response);
		if (!parsed.success) {
			throw new EvidenceVerifierUnavailableError("The evidence verifier returned an invalid key response");
		}
		return {
			evidenceReference: parsed.data.evidence_reference,
			keyStorage: parsed.data.key_storage,
			userAuthentication: parsed.data.user_authentication,
			certification: parsed.data.certification,
		};
	}

	private async request(body: Record<string, unknown>): Promise<unknown> {
		const abortController = new AbortController();
		const timeout = setTimeout(() => abortController.abort(), this.timeoutMilliseconds);
		try {
			const response = await fetch(this.endpoint, {
				method: "POST",
				headers: {
					"content-type": "application/json",
					...(this.bearerToken ? { authorization: `Bearer ${this.bearerToken}` } : {}),
				},
				body: JSON.stringify(body),
				signal: abortController.signal,
			});

			if (response.status === 401 || response.status === 403 || response.status === 422) {
				throw new EvidenceRejectedError("Wallet or key integrity evidence was rejected");
			}
			if (!response.ok) {
				throw new EvidenceVerifierUnavailableError(`Evidence verifier failed with HTTP ${response.status}`);
			}
			return await response.json();
		}
		catch (error) {
			if (error instanceof EvidenceRejectedError || error instanceof EvidenceVerifierUnavailableError) {
				throw error;
			}
			throw new EvidenceVerifierUnavailableError("Evidence verifier request failed");
		}
		finally {
			clearTimeout(timeout);
		}
	}
}

/**
 * Development-only verifier. Production startup rejects all DEV_* variables,
 * so this cannot silently become a production trust policy.
 */
export class DevelopmentWalletProviderEvidenceVerifier implements WalletProviderEvidenceVerifier {
	constructor(private readonly claims: Omit<VerifiedKeyEvidence, "evidenceReference">) { }

	async verifyActivation(): Promise<ActivationEvidenceResult> {
		return { evidenceReference: "development-unverified-activation" };
	}

	async verifyKeys(): Promise<VerifiedKeyEvidence> {
		return {
			evidenceReference: "development-unverified-key-evidence",
			...this.claims,
		};
	}
}

export class UnconfiguredWalletProviderEvidenceVerifier implements WalletProviderEvidenceVerifier {
	async verifyActivation(): Promise<never> {
		throw new EvidenceVerifierUnavailableError("Wallet Provider evidence verification is not configured");
	}

	async verifyKeys(): Promise<never> {
		throw new EvidenceVerifierUnavailableError("Wallet Provider evidence verification is not configured");
	}
}

function isRejectedResponse(value: unknown): boolean {
	return typeof value === "object" && value !== null && "verified" in value && value.verified === false;
}

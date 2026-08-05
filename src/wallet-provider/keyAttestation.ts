import { createHash, createPrivateKey, createPublicKey, KeyObject, X509Certificate } from "node:crypto";
import { readFile } from "node:fs/promises";
import { calculateJwkThumbprint, importJWK, JWK, SignJWT } from "jose";
import { z } from "zod";
import { removeCertificateMarkers } from "../util/util";

const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

export const publicJwkSchema = z.record(z.unknown())
	.superRefine((jwk, context) => {
		for (const member of PRIVATE_JWK_MEMBERS) {
			if (member in jwk) {
				context.addIssue({
					code: z.ZodIssueCode.custom,
					message: `Private JWK member '${member}' is forbidden`,
				});
			}
		}
	});

export type PublicJwk = Record<string, unknown>;

export type VerifiedKeyEvidence = {
	evidenceReference: string;
	keyStorage: string[];
	userAuthentication: string[];
	certification: string;
};

export type KeyAttestationClaims = {
	id: string;
	issuedAt: number;
	expiresAt: number;
	attestedKeys: PublicJwk[];
	verifiedEvidence: VerifiedKeyEvidence;
	statusListIndex: number;
	statusListUri: string;
	statusMaintenanceExpiresAt: number;
	nonce?: string;
};

export type WalletProviderSigner = {
	privateKey: KeyObject;
	x5c: string[];
};

export class InvalidPublicJwkError extends Error { }

export async function normalizeAndThumbprintPublicJwks(
	values: unknown[],
): Promise<{ jwks: PublicJwk[]; thumbprints: string[] }> {
	const jwks: PublicJwk[] = [];
	const thumbprints: string[] = [];

	for (const value of values) {
		let parsed: Record<string, unknown>;
		try {
			parsed = publicJwkSchema.parse(value);
		}
		catch (error) {
			throw new InvalidPublicJwkError(error instanceof Error ? error.message : "Invalid public JWK");
		}
		const expectedAlgorithm = algorithmForEcCurve(parsed.crv);
		if (
			parsed.kty !== "EC" ||
			typeof parsed.x !== "string" ||
			typeof parsed.y !== "string" ||
			!expectedAlgorithm ||
			(parsed.alg !== undefined && parsed.alg !== expectedAlgorithm)
		) {
			throw new InvalidPublicJwkError("Attested keys must be valid EC P-256, P-384, or P-521 public JWKs");
		}
		const jwk: JWK = {
			kty: parsed.kty,
			crv: parsed.crv as string,
			x: parsed.x,
			y: parsed.y,
			...(parsed.alg ? { alg: parsed.alg as string } : {}),
		};

		// Importing catches malformed coordinates and unsupported key shapes.
		try {
			await importJWK(jwk, expectedAlgorithm);
		}
		catch {
			throw new InvalidPublicJwkError("Attested key contains invalid elliptic-curve coordinates");
		}
		const thumbprint = await calculateJwkThumbprint(jwk, "sha256");
		if (thumbprints.includes(thumbprint)) {
			throw new InvalidPublicJwkError("The same public key cannot occur more than once in a key attestation");
		}

		jwks.push(jwk);
		thumbprints.push(thumbprint);
	}

	return { jwks, thumbprints };
}

export function hashJson(value: unknown): string {
	return createHash("sha256")
		.update(stableJson(value))
		.digest("hex");
}

export function hashToken(value: string): string {
	return createHash("sha256")
		.update(value, "utf8")
		.digest("hex");
}

export async function signKeyAttestation(
	claims: KeyAttestationClaims,
	signer: WalletProviderSigner,
): Promise<string> {
	const payload: Record<string, unknown> = {
		attested_keys: claims.attestedKeys,
		key_storage: claims.verifiedEvidence.keyStorage,
		user_authentication: claims.verifiedEvidence.userAuthentication,
		certification: claims.verifiedEvidence.certification,
		key_storage_status: {
			status: {
				status_list: {
					idx: claims.statusListIndex,
					uri: claims.statusListUri,
				},
			},
			exp: claims.statusMaintenanceExpiresAt,
		},
	};

	if (claims.nonce !== undefined) {
		payload.nonce = claims.nonce;
	}

	return await new SignJWT(payload)
		.setProtectedHeader({
			alg: "ES256",
			typ: "key-attestation+jwt",
			x5c: signer.x5c,
		})
		.setJti(claims.id)
		.setIssuedAt(claims.issuedAt)
		.setExpirationTime(claims.expiresAt)
		.sign(signer.privateKey);
}

export async function loadWalletProviderSigner(
	privateKeyPath: string,
	certificateChainPaths: string[],
): Promise<WalletProviderSigner> {
	if (certificateChainPaths.length === 0) {
		throw new Error("The Wallet Provider certificate chain cannot be empty");
	}

	const [privateKeyPem, ...certificateChain] = await Promise.all([
		readFile(privateKeyPath, "utf8"),
		...certificateChainPaths.map(path => readFile(path, "utf8")),
	]);
	const privateKey = createPrivateKey(privateKeyPem);
	const certificates = certificateChain.map(certificate => new X509Certificate(certificate));
	const leafCertificate = certificates[0];
	const privatePublicKey = createPublicKey(privateKey).export({ type: "spki", format: "der" });
	const certificatePublicKey = leafCertificate.publicKey.export({ type: "spki", format: "der" });

	if (!privatePublicKey.equals(certificatePublicKey)) {
		throw new Error("The Wallet Provider private key does not match the leaf certificate");
	}
	if (privateKey.asymmetricKeyType !== "ec" || privateKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
		throw new Error("The Wallet Provider signing key must be an EC P-256 key for ES256");
	}
	const now = Date.now();
	for (const certificate of certificates) {
		if (now < Date.parse(certificate.validFrom) || now >= Date.parse(certificate.validTo)) {
			throw new Error("The Wallet Provider certificate chain contains an expired or not-yet-valid certificate");
		}
	}
	for (let index = 0; index < certificates.length - 1; index++) {
		if (!certificates[index].verify(certificates[index + 1].publicKey)) {
			throw new Error("The Wallet Provider certificate chain is not ordered leaf-to-intermediate");
		}
	}

	return {
		privateKey,
		x5c: certificateChain.map(removeCertificateMarkers),
	};
}

function stableJson(value: unknown): string {
	if (Array.isArray(value)) {
		return `[${value.map(stableJson).join(",")}]`;
	}
	if (value !== null && typeof value === "object") {
		return `{${Object.entries(value as Record<string, unknown>)
			.sort(([left], [right]) => left.localeCompare(right))
			.map(([key, child]) => `${JSON.stringify(key)}:${stableJson(child)}`)
			.join(",")}}`;
	}
	const serialized = JSON.stringify(value);
	return serialized === undefined ? "null" : serialized;
}

function algorithmForEcCurve(curve: unknown): "ES256" | "ES384" | "ES512" | undefined {
	switch (curve) {
		case "P-256": return "ES256";
		case "P-384": return "ES384";
		case "P-521": return "ES512";
		default: return undefined;
	}
}

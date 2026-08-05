import { deflateSync } from "node:zlib";
import { SignJWT } from "jose";
import { WalletProviderSigner } from "./keyAttestation";

export const STATUS_LIST_BITS = 1;
export const VALID_STATUS = 0;
export const INVALID_STATUS = 1;

export function encodeStatusList(capacity: number, invalidIndexes: number[]): string {
	if (!Number.isSafeInteger(capacity) || capacity <= 0) {
		throw new Error("Status List capacity must be a positive integer");
	}

	const bytes = Buffer.alloc(Math.ceil(capacity / 8));
	for (const index of invalidIndexes) {
		if (!Number.isSafeInteger(index) || index < 0 || index >= capacity) {
			throw new Error(`Status List index ${index} is out of bounds`);
		}
		bytes[Math.floor(index / 8)] |= INVALID_STATUS << (index % 8);
	}

	return deflateSync(bytes, { level: 9 }).toString("base64url");
}

export async function signStatusListToken(options: {
	uri: string;
	capacity: number;
	invalidIndexes: number[];
	issuedAt: number;
	expiresAt: number;
	ttl: number;
	signer: WalletProviderSigner;
}): Promise<string> {
	return await new SignJWT({
		ttl: options.ttl,
		status_list: {
			bits: STATUS_LIST_BITS,
			lst: encodeStatusList(options.capacity, options.invalidIndexes),
		},
	})
		.setProtectedHeader({
			alg: "ES256",
			typ: "statuslist+jwt",
			x5c: options.signer.x5c,
		})
		.setSubject(options.uri)
		.setIssuedAt(options.issuedAt)
		.setExpirationTime(options.expiresAt)
		.sign(options.signer.privateKey);
}

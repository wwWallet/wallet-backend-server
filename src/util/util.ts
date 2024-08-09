import * as crypto from 'crypto';
import base64url from "base64url";
import { Err, Ok, Result } from 'ts-results';


export function isResult<T>(a: T | Result<T, unknown>): a is Result<T, unknown> {
	return a instanceof Object && "val" in a && "ok" in a && "err" in a;
}

/**
*
* @param type is the 'type' attribute of a VC in JSON-LD format
*/
export function decideVerifiableCredentialType(type: string[]): 'Diploma' | 'Attestation' | 'Presentation' {

	if (type.includes('VerifiablePresentation')) return 'Presentation';


	for (const t of type) {
		const lower = t.toLowerCase();
		if (lower.includes('europass') ||
			lower.includes('universitydegree') ||
			lower.includes('diploma')) {

			return 'Diploma';
		}
	}

	return 'Attestation';
}

export function jsonStringifyTaggedBinary(value: any): string {
	return JSON.stringify(value, replacerBufferToTaggedBase64Url);
}

export function jsonParseTaggedBinary(json: string): any {
	return JSON.parse(json, reviverTaggedBase64UrlToBuffer);
}

export function replacerBufferToTaggedBase64Url(key: string, value: any): any {
	if (this[key] instanceof Buffer) {
		return { '$b64u': base64url.encode(this[key]) };
	} else {
		return value;
	}
}

export function reviverTaggedBase64UrlToBuffer(key: string, value: any): any {
	if (value?.$b64u !== undefined) {
		return base64url.toBuffer(value["$b64u"]);
	} else {
		return value;
	}
}


export type EtagUpdate<T> = {
	expectTag: string,
	newValue: T,
}

/**
 * Return `newValue` if and only if `comparator` returns a value strictly equal
 * (`===`) to `expectTag` given `currentValue`.
 */
export function checkedUpdate<T, U>(
	expectTag: U,
	tagFunc: (value: T) => U,
	{ currentValue, newValue }: { currentValue: T, newValue: T },
): Result<T, void> {
	if (currentValue === newValue) {
		// Change has already been applied (if T supports === equality)
		return Ok(newValue);

	} else {
		const currentTag = tagFunc(currentValue)
		if (currentTag === expectTag) {
			// Expected change
			return Ok(newValue);

		} else {
			if (currentTag === tagFunc(newValue)) {
				// Change has already been applied (if T does not support === equality)
				return Ok(newValue);
			}
		}
		return Err.EMPTY;
	}
}

export function isValidUri(uri: string): boolean {
	try {
		return Boolean(new URL(uri));
	}
	catch (e) {
		return false;
	}
}

export async function generateCodeChallengeFromVerifier(v: any) {
	try {
		const challenge = base64url.encode(crypto
			.createHash("sha256")
			.update(v)
			.digest());
		console.log("code chall = ", challenge)
		return challenge;
	}
	catch(e) {
		console.log("Failed to generate code challenge")
		return null;
	}
}

export function generateCodeVerifier() {
	try {
		const verifier = base64url.encode(crypto.randomBytes(32));
		console.log("ver = ", verifier)
		return verifier;
	}
	catch(e) {
		console.log("Failed to generate code verifier")
		return null;
	}
}


export const verifiablePresentationSchemaURL = "https://api-pilot.ebsi.eu/trusted-schemas-registry/v2/schemas/zFj7VdCiHdG4GB6fezdAUKhDEuxFR2bri2ihKLkiZYpE9";

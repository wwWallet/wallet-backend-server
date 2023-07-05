
import * as randomstring from 'randomstring';
import * as crypto from 'crypto';
import base64url from "base64url";

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


export function isValidUri(uri: string): boolean {
	try {
		return Boolean(new URL(uri));
	}
	catch (e) {
		return false;
	}
}

export async function generateCodeChallengeFromVerifier(v: any) {
	const base64Digest = crypto
		.createHash("sha256")
		.update(v)
		.digest("base64");
	console.log(base64Digest); // +PCBxoCJMdDloUVl1ctjvA6VNbY6fTg1P7PNhymbydM=

	return base64url.fromBase64(base64Digest);
}

export function generateCodeVerifier() {
	return randomstring.generate(128);
}


export const verifiablePresentationSchemaURL = "https://api-pilot.ebsi.eu/trusted-schemas-registry/v2/schemas/zFj7VdCiHdG4GB6fezdAUKhDEuxFR2bri2ihKLkiZYpE9";
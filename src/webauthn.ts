import * as cbor from 'cbor-x';
import { convertAAGUIDToString } from '@simplewebauthn/server/helpers';
import { config } from '../config';
import { UserId, WebauthnCredentialEntity } from './entities/user.entity';


export function getRpId(): string {
	return config.webauthn.rp.id;
}

export function makeCreateOptions({
	challenge,
	prfSalt,
	user,
}: {
	challenge: Buffer,
	prfSalt?: Buffer,
	user: {
		uuid: UserId,
		name: string,
		displayName: string,
		webauthnCredentials?: WebauthnCredentialEntity[],
	},
}) {
	return {
		publicKey: {
			rp: config.webauthn.rp,
			user: {
				id: user.uuid.asUserHandle(),
				name: user.name,
				displayName: user.displayName,
			},
			challenge: challenge,
			pubKeyCredParams: [
				{ type: "public-key", alg: -7 },
				{ type: "public-key", alg: -8 },
				{ type: "public-key", alg: -257 },
			],
			excludeCredentials: (user.webauthnCredentials || []).map(cred => cred.getCredentialDescriptor()),
			authenticatorSelection: {
				requireResidentKey: true,
				residentKey: "required",
				userVerification: "required",
			},
			attestation: config.webauthn.attestation,
			extensions: {
				credProps: true,
				prf: {
					eval: prfSalt
						? { first: prfSalt }
						: undefined,
				},
			},
		},
	};
}

export function makeGetOptions({
	challenge,
	user,
}: {
	challenge: Buffer,
	user?: {
		webauthnCredentials: WebauthnCredentialEntity[],
	},
}) {
	return {
		publicKey: {
			rpId: getRpId(),
			challenge: challenge,
			allowCredentials: (user?.webauthnCredentials || []).map(cred => cred.getCredentialDescriptor()),
			userVerification: "required",
		},
	};
}

/**
 * Convert the given attestation object into one with the `"none"` attestation
 * statement format.
 */
export function stripAttestationStatement(attObj: Buffer | Uint8Array): Buffer {
	const originalAttestationObject = cbor.decode(attObj);
	const encoder = new cbor.Encoder({ useRecords: false, variableMapSize: true });
	const enc = encoder.encode({
		fmt: "none",
		authData: originalAttestationObject.authData,
		attStmt: {},
	});
	return enc;
}

type AuthenticatorFlags = {
	userPresent: boolean;              // UP
	userVerified: boolean;             // UV
	backupEligibility: boolean;        // BE
	backupState: boolean;              // BS
	attestedCredentialData: boolean;   // AT
	extensionData: boolean;            // ED
	rawFlagsByte: number;
};

function toUint8Array(value: Buffer | Uint8Array | ArrayBuffer): Uint8Array {
	if (value instanceof Uint8Array) {
		return value;
	}
	return new Uint8Array(value);
}

function parseAuthenticatorFlagsFromAuthenticatorData(authenticatorData: Buffer | Uint8Array | ArrayBuffer): AuthenticatorFlags {
	const data = toUint8Array(authenticatorData);

	if (data.length < 37) {
		return {
			userPresent: false,
			userVerified: false,
			backupEligibility: false,
			backupState: false,
			attestedCredentialData: false,
			extensionData: false,
			rawFlagsByte: 0,
		};
	}

	const flags = data[32];

	return {
		userPresent: Boolean(flags & 0x01),             // bit 0 - UP
		userVerified: Boolean(flags & 0x04),            // bit 2 - UV
		backupEligibility: Boolean(flags & 0x08),       // bit 3 - BE
		backupState: Boolean(flags & 0x10),             // bit 4 - BS
		attestedCredentialData: Boolean(flags & 0x40),  // bit 6 - AT
		extensionData: Boolean(flags & 0x80),           // bit 7 - ED
		rawFlagsByte: flags,
	};
}

export function parseAuthenticatorFlags(input: Buffer | Uint8Array,isAttestation: boolean): AuthenticatorFlags {
	if (isAttestation) {
		const decoded = cbor.decode(input);

		if (!decoded.authData) {
			return {
				userPresent: false,
				userVerified: false,
				backupEligibility: false,
				backupState: false,
				attestedCredentialData: false,
				extensionData: false,
				rawFlagsByte: 0,
			};
		}

		return parseAuthenticatorFlagsFromAuthenticatorData(decoded.authData);
	}

	return parseAuthenticatorFlagsFromAuthenticatorData(input);
}

export function getAaguidFromAttestationObject(
	attestationObject: Buffer | Uint8Array,
): string | undefined {
	const attestation = cbor.decode(attestationObject);
	const authData = toUint8Array(attestation.authData);

	const attestedCredentialData = (authData[32] & 0x40) !== 0;
	if (!attestedCredentialData || authData.length < 53) {
		return undefined;
	}

	const aaguid = authData.slice(37, 53);
	return convertAAGUIDToString(aaguid);
}

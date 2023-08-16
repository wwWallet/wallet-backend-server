import config from '../config';
import { WebauthnCredentialEntity } from './entities/user.entity';


export function makeCreateOptions({
	challenge,
	prfSalt,
	user,
}: {
	challenge: Buffer,
	prfSalt?: Buffer,
	user: {
		webauthnUserHandle: string,
		name: string,
		displayName: string,
		webauthnCredentials?: WebauthnCredentialEntity[],
	},
}) {
	return {
		publicKey: {
			rp: config.webauthn.rp,
			user: {
				id: Buffer.from(user.webauthnUserHandle, "utf8"),
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
			rpId: config.webauthn.rp.id,
			challenge: challenge,
			allowCredentials: (user?.webauthnCredentials || []).map(cred => cred.getCredentialDescriptor()),
			userVerification: "required",
		},
	};
}

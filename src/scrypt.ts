import crypto from "node:crypto";
import base64url from "base64url";
import { Err, Ok, Result } from "ts-results";


// Settings for new password hashes
// Best practice guidelines from https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
const keyLen: number = 64;
const cost: number = 131072; // 2^17
const blockSize: number = 8;
const maxmem: number = 128 * cost * blockSize * 2;


function parseParams(passwordHash: string): Result<{ salt: Buffer, keyLen: number, cost: number, blockSize: number }, void> {
	try {
		if (!passwordHash.startsWith("$")) {
			return Err.EMPTY;
		}

		const splits = passwordHash.split('$');
		const keyLen = parseInt(splits[1], 10);
		const cost = parseInt(splits[2], 10);
		const blockSize = parseInt(splits[3], 10);
		const salt = base64url.toBuffer(splits[4]);
		return Ok({ salt, keyLen, cost, blockSize });

	} catch (e) {
		return Err.EMPTY;
	}
}

async function computeScrypt(password: string, salt: Buffer, keyLen: number, cost: number, blockSize: number): Promise<string> {
	return new Promise((resolve, reject) => {
		crypto.scrypt(
			Buffer.from(password, "utf8"),
			salt,
			keyLen,
			{ cost, blockSize, maxmem },
			(err, derivedKey) => {
				if (err) {
					console.error("Failed to compute scrypt hash", err);
					reject(err);
				} else {
					const result = "$" + [keyLen, cost, blockSize, base64url.encode(salt), base64url.encode(derivedKey)].join("$");
					resolve(result);
				}
			},
		);
	});
}

export async function createHash(password: string): Promise<string> {
	return await computeScrypt(password, crypto.randomBytes(32), keyLen, cost, blockSize);
}

/**
 * @return Ok(true) if password matches; Ok(false) if password is scrypt-hashed but does not match; Err(void) if password is not scrypt-hashed.
 */
export async function verifyHash(password: string, scryptHash: string): Promise<Result<boolean, void>> {
	const decodeRes = parseParams(scryptHash);
	if (decodeRes.ok) {
		const { salt, keyLen, cost, blockSize } = decodeRes.val;
		const encoded = await computeScrypt(password, salt, keyLen, cost, blockSize);
		return Ok(encoded === scryptHash);
	} else {
		return Err.EMPTY;
	}
}

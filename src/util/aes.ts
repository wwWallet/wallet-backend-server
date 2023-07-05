
import crypto from 'node:crypto';
const algorithm = 'aes-256-cbc'; //Using AES encryption
const key = crypto.randomBytes(32); // could be
const iv = crypto.randomBytes(16);

export class AES {

	//Encrypting text
	static encrypt(text: string) {
		let cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
		let encrypted = cipher.update(text);
		encrypted = Buffer.concat([encrypted, cipher.final()]);
		return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
	}

	// Decrypting text
	static decrypt(text: any) {
		let iv = Buffer.from(text.iv, 'hex');
		let encryptedText = Buffer.from(text.encryptedData, 'hex');
		let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
		let decrypted = decipher.update(encryptedText);
		decrypted = Buffer.concat([decrypted, decipher.final()]);
		return decrypted.toString();
	}
}

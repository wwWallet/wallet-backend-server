import { X509Certificate, X509ChainBuilder, cryptoProvider } from '@peculiar/x509';
import { webcrypto } from 'crypto';

cryptoProvider.set(webcrypto as any);

export interface VerifyChainParams {
	trustedRoot: string | Buffer;
	leaf: string | Buffer;
	intermediates?: Array<string | Buffer>;
}

/**
 * Verifies an x5c certificate chain against a trusted root.
 */
export async function verifyCertificateChain({ trustedRoot, leaf, intermediates = [] }: VerifyChainParams): Promise<boolean> {
	try {
		const rootCa = new X509Certificate(trustedRoot);
		const leafCert = new X509Certificate(leaf);
		const intermediateCerts = intermediates.map(cert => new X509Certificate(cert));

		const chainBuilder = new X509ChainBuilder({
			certificates: [rootCa, ...intermediateCerts]
		});

		const builtChain = await chainBuilder.build(leafCert);

		const builtRoot = builtChain[builtChain.length - 1];
		if (builtRoot.thumbprint !== rootCa.thumbprint) {
			throw new Error("Chain is valid, but does not anchor to the expected root.");
		}

		return true;

	} catch (error: any) {
		console.error("Certificate verification error:", error.message);
		return false;
	}
}
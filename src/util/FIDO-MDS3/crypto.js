const { X509Certificate, X509ChainBuilder, cryptoProvider } = require('@peculiar/x509');
const { webcrypto } = require('crypto');

cryptoProvider.set(webcrypto);

/**
 * Verifies an x5c certificate chain against a trusted root.
 * 
 * @param {Object} params - The certificate chain components.
 * @param {string|Buffer} params.trustedRoot - The root CA certificate (PEM, Base64, or Buffer).
 * @param {string|Buffer} params.leaf - The end-entity certificate (Base64).
 * @param {Array<string|Buffer>} [params.intermediates=[]] - Array of intermediate certificates.
 * @returns {Promise<boolean>} True if the chain is valid, false otherwise.
 */
async function verifyCertificateChain({ trustedRoot, leaf, intermediates = [] }) {
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
      console.error("Certificate chain does not terminate at the trusted root.");
      return false;
    }

    return true;

  } catch (error) {
    console.error("Certificate verification error:", error.message);
    return false;
  }
}

module.exports = {
  verifyCertificateChain
};
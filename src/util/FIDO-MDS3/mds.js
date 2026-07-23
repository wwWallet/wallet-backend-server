const fs = require('fs').promises;
const crypto = require('crypto');
const config = require('./config');
const { verifyCertificateChain, base64ToArrayBuffer, bufferToArrayBuffer } = require('./crypto');

async function validateBlobAuthenticity(rawBlob) {
  const parts = rawBlob.trim().split('.');
  if (parts.length !== 3) throw new Error("Invalid JWT BLOB format.");

  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  if (!header.x5c || !header.x5c.length) throw new Error("Missing x5c chain.");

  const rootPem = await fs.readFile(config.paths.rootCert);
  const trustedRootX509 = new crypto.X509Certificate(rootPem);

  const isChainValid = await verifyCertificateChain({
    trustedRoot: rootPem,
    leaf: header.x5c[0],
    intermediates: header.x5c.slice(1)
  });

  if (!isChainValid) throw new Error("x5c Certificate Chain validation failed.");

  const leafX509 = new crypto.X509Certificate(Buffer.from(header.x5c[0], 'base64'));
  const dataToVerify = Buffer.from(`${parts[0]}.${parts[1]}`);
  const signature = Buffer.from(parts[2], 'base64url');

  let hashAlg = 'SHA256';
  if (header.alg === 'ES384' || header.alg === 'RS384') hashAlg = 'SHA384';
  if (header.alg === 'ES512' || header.alg === 'RS512') hashAlg = 'SHA512';

  const isValidSignature = crypto.createVerify(hashAlg)
    .update(dataToVerify)
    .verify(leafX509.publicKey, signature);

  if (!isValidSignature) throw new Error("JWT signature verification failed!");
}

function parseAndFormatBlob(rawBlob) {
  const parts = rawBlob.trim().split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  
  const map = {};
  if (payload.entries && Array.isArray(payload.entries)) {
    payload.entries.forEach(entry => {
      if (entry.aaguid) map[entry.aaguid] = entry.metadataStatement;
    });
  }
  
  return { payloadMap: map, nextUpdate: payload.nextUpdate };
}

module.exports = {
  validateBlobAuthenticity,
  parseAndFormatBlob
};
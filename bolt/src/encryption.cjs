const crypto = require('node:crypto');
const fs = require('node:fs')

// Helper function to encode a Buffer into a Base64URL string
function base64url(buffer) {
  return buffer.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

// Helper function to decode a Base64URL string back into a raw binary Buffer
function base64urlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

/**
 * Encrypts a binary file into an RFC 7516 compliant compact JWE token.
 * Uses RSA-OAEP-256 for key wrapping and AES-256-GCM for content encryption.
 *
 * @param {Buffer} plaintextMasterKey - raw key data (luks master key)
 * @param {string} publicKeyJwkPaths - array of paths to jwk key files
 * @returns {string} base64 encoded jwe
 */
function encryptKeyToJwe(plaintextMasterKey, publicKeyJwkPaths) {
    const cek = crypto.randomBytes(32); // 256 bits required for A256GCM
    const iv = crypto.randomBytes(12);  // 96 bits - standard size for AES-GCM

    const protected = {
        enc: "A256GCM"
    }
    const protectedHeaderB64 = base64url(Buffer.from(JSON.stringify(protected)));
    const jwe = {
        protected: protectedHeaderB64,
        iv: base64url(iv),
        recipients : []
    }

    // Symmetrically encrypt the plaintext key payload
    const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv);

    // Bind the protected header ASCII representation as Authenticated Additional Data (AAD)
    cipher.setAAD(Buffer.from(protectedHeaderB64, 'ascii'));

    jwe.ciphertext = base64url(Buffer.concat([cipher.update(plaintextMasterKey), cipher.final()]));
    jwe.tag = base64url(cipher.getAuthTag());

    for (publicKeyJwkPath of publicKeyJwkPaths) {
        const publicKeyJwk = JSON.parse(fs.readFileSync(publicKeyJwkPath, 'utf8'));
        // Convert the raw JWK JSON metadata into a native crypto KeyObject
        const publicKey = crypto.createPublicKey({ key: publicKeyJwk, format: 'jwk' });

        // Asymmetrically wrap the CEK using RSA-OAEP-256
        const encryptedCek = crypto.publicEncrypt({
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256' // Mandated for OAEP-256 variant
        }, cek);

        jwe.recipients.push({
            encrypted_key: base64url(encryptedCek),
            header: {
                alg: publicKeyJwk.alg,
                kid: publicKeyJwk.kid
            }
        })
    }

    return base64url(Buffer.from(JSON.stringify(jwe)));
}

module.exports = {
    encryptKeyToJwe,
    base64url,
    base64urlDecode
}
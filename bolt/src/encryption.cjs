const crypto = require('node:crypto');
const fs = require('node:fs')
const { exec, spawnSync } = require('./utils.cjs');
const { default: assert } = require('node:assert');

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

    return Buffer.from(JSON.stringify(jwe),'utf-8').toString('base64')
    // TODO: or should that be url-encoded? return base64url(Buffer.from(JSON.stringify(jwe)));
}

function createLuksImage(inputLuks, plaintextMasterKey) {
    const blockSize = 4096;
    const luksOffsetSectors512b = 576;
    const luksReduceSizeSectors512b = 2 * 576;

    // add space for the LUKS header + tmp space for LUKS reencryption
    exec(`dd if=/dev/zero bs=512 count=${luksReduceSizeSectors512b} of=${inputLuks} conv=notrunc oflag=append`);
    // finally, convert the image to luks in-place; the master key is read
    // via stdin, directly from plaintextMasterKey Buffer
    const spawnRet = spawnSync('cryptsetup', [
        'reencrypt',
        '--encrypt',
        '--type','luks2',
        '--sector-size', blockSize,
        '--offset',luksOffsetSectors512b,
        '--disable-locks',
        '--force-offline-reencrypt',
        '--reduce-device-size', `${luksReduceSizeSectors512b}S`,
        '--key-file','-',
        '--key-size','512',
        '--batch-mode',
        '--pbkdf','pbkdf2',
        '--pbkdf-force-iterations','1000',
        '--pbkdf-memory','0',
        '--pbkdf-parallel','0',
        '--luks2-metadata-size','16k',
        '--luks2-keyslots-size','256k',
        inputLuks],
        { input: plaintextMasterKey });

    if (spawnRet.status != 0) {
        throw new Error(`cryptsetup returned error; spawn returned: ${spawnRet}`);
    }

    // trim the 'workspace'; it was only needed by cryptsetup reencrypt
    const junkSizeAtEnd = luksOffsetSectors512b * 512;
    const currentFileSize = fs.statSync(inputLuks).size;
    fs.truncateSync(inputLuks, currentFileSize - junkSizeAtEnd);
}


function parseLuksData(image) {
    luksInfo = exec(`cryptsetup luksDump ${image}`).trim().split('\n');
    let match, version, inKeyslots = false, cipher, salt = '', parsingsalt = false, keyLength;
    for (line of luksInfo) {
        if (match = line.match(/Version:\s+(\d+)/)) {
            version = match[1]
        } else if (match = line.match(/^Keyslots:/)) {
            inKeyslots = true;
        } else if (inKeyslots && (match = line.match(/^\s*Cipher:\s*([^\s]+)/))) {
            cipher = match[1];
        } else if (inKeyslots && (match = line.match(/Cipher key: (\d+) bits/))) {
            keyLength = match[1];
        } else if (inKeyslots && (match = line.match(/^\s*Salt:\s*([a-f0-9\s]+)/))) {
            salt += match[1].trim().replaceAll(' ','');
            parsingsalt = true;
        } else if (parsingsalt && ( match = line.match(/^\s*([a-f0-9 ]+)$/))) {
            salt += match[1].trim().replaceAll(' ','');
        } else {
            parsingsalt = false;
            if (line.match(/Tokens/)) {
                inKeyslots = false;
            }
        }
    }
    const encodedSalt = Buffer.from(salt, 'hex').toString('base64');
    let ret = {version, cipher, salt: encodedSalt, keyLength};
    if (! [version, cipher, encodedSalt, keyLength].every(str => str && str.trim().length > 0)) {
        throw new Error(`failed to parse some luks data: ${ret}`)
    }
    return ret;
}

module.exports = {
    encryptKeyToJwe,
    base64url,
    base64urlDecode,
    createLuksImage,
    parseLuksData
}
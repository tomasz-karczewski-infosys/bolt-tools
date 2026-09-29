const { exit } = require('process');
const encryption = require('../src/encryption.cjs')
const fs = require('fs');
const crypto = require('crypto');
const { assert } = require('console');

function encryptKeyToJwe_simple_test() {
    {
        // Generate the keypair directly into JWK format
        let { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'jwk' },
            privateKeyEncoding: { type: 'pkcs1', format: 'jwk' }
        });
        publicKey.alg = 'RSA-OAEP-256';
        publicKey.kid = 'recipient-public-key-id-1';

        var jwk_rsa_1_public = publicKey;
    }

    {
        let { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'jwk' },
            privateKeyEncoding: { type: 'pkcs1', format: 'jwk' }
        });
       publicKey.alg = 'RSA-OAEP-256';
       publicKey.kid = 'recipient-public-key-id-2';

        var jwk_rsa_2_public = publicKey;
    }

    const plaintextKey = crypto.randomBytes(64);

    fs.writeFileSync('public1.jwk', JSON.stringify(jwk_rsa_1_public, null, 2));
    fs.writeFileSync('public2.jwk', JSON.stringify(jwk_rsa_2_public, null, 2));

    let jwk = encryption.encryptKeyToJwe(plaintextKey, ['public1.jwk', 'public2.jwk'])
    let decodedJwk = JSON.parse(encryption.base64urlDecode(jwk));
    // console.info(`decoded jwk: \n\n\n${JSON.stringify(decodedJwk, null, 2)}`);

    assert(["recipient-public-key-id-1", "recipient-public-key-id-2"].find(val => val === decodedJwk.recipients[0].header.kid));
    assert(["recipient-public-key-id-1", "recipient-public-key-id-2"].find(val => val === decodedJwk.recipients[1].header.kid));
}

encryptKeyToJwe_simple_test();
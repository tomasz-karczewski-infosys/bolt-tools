const { exit } = require('process');
const encryption = require('../src/encryption.cjs')
const fs = require('fs');
const crypto = require('crypto');
const { assert } = require('console');
const strictAssert = require('node:assert/strict');
const { spawnSync } = require('../src/utils.cjs');

function spawnSync_stdin_buffer_test() {
    const input = Buffer.from('ignored line\nmatching café\nanother line\n', 'utf8');
    const result = spawnSync('grep', ['matching'], { input });

    //console.log(`stdout: ${result.stdout.toString()}`);
    //console.log(`stderr: ${result.stderr.toString()}`);

    strictAssert.ifError(result.error);
    strictAssert.equal(result.status, 0);
    strictAssert.equal(result.stdout, 'matching café\n');
    strictAssert.equal(result.stderr, '');
}

function encryptKeyToJwe_simple_test() {
    if (!(fs.existsSync('public1.jwk') && fs.existsSync('public2.jwk') && fs.existsSync('private1.jwk') && fs.existsSync('private2.jwk'))) {
        {
            // Generate the keypair directly into JWK format
            let { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
                modulusLength: 2048,
                publicKeyEncoding: { type: 'pkcs1', format: 'jwk' },
                privateKeyEncoding: { type: 'pkcs1', format: 'jwk' }
            });
            publicKey.alg = 'RSA-OAEP-256';
            publicKey.kid = 'recipient-public-key-id-1';
            privateKey.alg = 'RSA-OAEP-256';
            privateKey.kid = 'recipient-public-key-id-1';

            var jwk_rsa_1_public = publicKey;
            var jwk_rsa_1_private = privateKey;
        }

        {
            let { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
                modulusLength: 2048,
                publicKeyEncoding: { type: 'pkcs1', format: 'jwk' },
                privateKeyEncoding: { type: 'pkcs1', format: 'jwk' }
            });
            publicKey.alg = 'RSA-OAEP-256';
            publicKey.kid = 'recipient-public-key-id-2';
            privateKey.alg = 'RSA-OAEP-256';
            privateKey.kid = 'recipient-public-key-id-1';

            var jwk_rsa_2_public = publicKey;
            var jwk_rsa_2_private = privateKey;
        }
        fs.writeFileSync('public1.jwk', JSON.stringify(jwk_rsa_1_public, null, 2));
        fs.writeFileSync('public2.jwk', JSON.stringify(jwk_rsa_2_public, null, 2));
        fs.writeFileSync('private1.jwk', JSON.stringify(jwk_rsa_1_private, null, 2));
        fs.writeFileSync('private2.jwk', JSON.stringify(jwk_rsa_2_private, null, 2));
    }

    const plaintextKey = crypto.randomBytes(64);

    let jwk = encryption.encryptKeyToJwe(plaintextKey, ['public1.jwk', 'public2.jwk'])
    let decodedJwk = JSON.parse(encryption.base64urlDecode(jwk));
    // console.info(`decoded jwk: \n\n\n${JSON.stringify(decodedJwk, null, 2)}`);

    assert(["recipient-public-key-id-1", "recipient-public-key-id-2"].find(val => val === decodedJwk.recipients[0].header.kid));
    assert(["recipient-public-key-id-1", "recipient-public-key-id-2"].find(val => val === decodedJwk.recipients[1].header.kid));
}

function test_parseLuksData() {
    let luksMetadata = encryption.parseLuksData('test_luks_image');
    console.info(`luksMetadata: ${JSON.stringify(luksMetadata)} version: ${luksMetadata.version} cipher:${luksMetadata.cipher} salt:${luksMetadata.salt}`)
}

spawnSync_stdin_buffer_test();
encryptKeyToJwe_simple_test();
test_parseLuksData();
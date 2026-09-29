/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

const { makeArtifactManifest } = require('./artifact-manifest.cjs');
const sha256 = require('./tools/sha256.cjs');
const { ZIPPackageBuilder } = require('./ZIPPackageBuilder.cjs');
const { commonOptions } = require('./commonOptions.cjs');
const { exec, execv, assertFile } = require('./utils.cjs');
const { statSync, mkdirSync, rmSync, readFileSync } = require('node:fs');
const crypto = require('node:crypto');
const encryption = require('./encryption.cjs')

function validateConfig(config) {
  if ((config.packageType === "base" || config.packageType === "runtime" || config.packageType === "application") &&
    typeof config.id === "string" &&
    typeof config.version === "string" &&
    typeof config.versionName === "string" &&
    typeof config.name === "string") {
    return;
  } else {
    throw new Error(`Invalid config:\n ${JSON.stringify(config, null, 2)}`);
  }
}

function hasRalfpack() {
  return exec(`which ralfpack >/dev/null; echo $?`).trim() === "0";
}

function ralfpackSignArgs(options) {
  const args = [];
  if (options.key) args.push("--key", options.key);
  if (options.cert) args.push("--certificate", options.cert);
  return args;
}

function ralfpackSign(packageFile, options) {
  execv("ralfpack", ["sign", ...ralfpackSignArgs(options), packageFile]);
}

function pack(configFile, content, options) {
  assertFile(configFile);
  assertFile(content);
  const config = JSON.parse(readFileSync(configFile));
  validateConfig(config);
  const output = `${config.id}+${config.version}`;

  if (hasRalfpack() && !options.encrypt) {
    execv("ralfpack", ["create", "--config", configFile, "--content", content, ...ralfpackSignArgs(options), "--image-format", "erofs.lz4", `${output}.bolt`]);
  } else {
    rmSync(output, { recursive: true, force: true });
    mkdirSync(output, { recursive: true });
    try {
      packInternal(content, config, output, options);
    } finally {
      rmSync(output, { recursive: true, force: true });
    }
  }

  console.log(`Prepared ${output}.bolt package from ${configFile} and ${content}`);
}

function packInternal(content, config, output, options) {
  const builder = new ZIPPackageBuilder(output + ".bolt", output);

  const erofsTmpFile = output + '/erofs';
  execv('mkfs.erofs', ['-zlz4', '--all-root', '--tar', '--gzip', erofsTmpFile, content]);
  const erofsTmpFileStat = statSync(erofsTmpFile);
  const verityInfo = execv('veritysetup',
    ['format', erofsTmpFile, erofsTmpFile, `--hash-offset=${erofsTmpFileStat.size}`]
  ).trim().split('\n');
  let rootHash;
  let salt;

  for (let line of verityInfo) {
    if (line.startsWith('Root hash:')) {
      rootHash = line.substring('Root hash:'.length).trim();
    } else if (line.startsWith('Salt:')) {
      salt = line.substring('Salt:'.length).trim();
    }
  }

  if (!(typeof rootHash === "string" && rootHash.match(/^[0-9a-f]+$/) && typeof salt === "string" && salt.match(/^[0-9a-f]+$/))) {
    console.error(`Cannot find "Root hash" and/or "Salt" in veritysetup command output!`);
    process.exit(-1);
  }

  const contentInfo = builder.importFile(erofsTmpFile);
  const configInfo = builder.importObject(config);

  const manifest = makeArtifactManifest({
    type: config.packageType,
    configSize: configInfo.size,
    configDigest: configInfo.digest,
    contentSize: contentInfo.size,
    contentDigest: contentInfo.digest,
  });

  Object.assign(manifest.layers[0], {
    mediaType: "application/vnd.rdk.package.content.layer.v1.erofs+dmverity",
    annotations: {
      "org.rdk.package.content.dmverity.roothash": rootHash,
      "org.rdk.package.content.dmverity.offset": "" + erofsTmpFileStat.size,
      "org.rdk.package.content.dmverity.salt": salt,
    }
  });

  if (options.encrypt) {
    const plaintextMasterKey = crypto.randomBytes(64);
    try {
      let jweTokenString = encryption.encryptKeyToJwe(plaintextMasterKey, options["encrypt-key"]);
      manifest.layers[0].mediaType += "+encrypted";
      Object.assign(manifest.layers[0].annotations,
        {
          // "org.opencontainers.image.dmcrypt.cipher": "aes-xts-plain64",
          // "org.opencontainers.image.dmcrypt.keysize": "512",
          // "org.opencontainers.image.dmcrypt.type": "luks2",
          "org.opencontainers.image.enc.keys.jwe": jweTokenString
        });
    } finally {
      if (plaintextMasterKey) {
        plaintextMasterKey.fill(0);
      }
    }
  }

  const manifestInfo = builder.importObject(manifest);

  writeOCIIndex(builder, { manifestInfo, id: config.id, options, signWithRalfpack: false });
}

function writeOCIIndex(builder, { manifestInfo, id, options, signWithRalfpack }) {
  const index = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "manifests": [
      {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": manifestInfo.digest,
        "size": manifestInfo.size,
        "annotations": {
          "org.opencontainers.image.ref.name": id
        }
      }
    ]
  };

  const useRalfpack = options.key && (signWithRalfpack ?? hasRalfpack());

  if (options.key && !useRalfpack) {
    // https://github.com/rdkcentral/oci-package-spec/blob/main/format.md#signature-layer-payload
    const signatureLayerPayload = {
      "critical": {
        "identity": {
          "docker-reference": id,
        },
        "image": {
          "docker-manifest-digest": `${manifestInfo.digest}`,
        },
        "type": "cosign container image signature",
      },
      "optional": null
    };
    const signatureLayerPayloadStr = JSON.stringify(signatureLayerPayload, null, 2);
    const signatureLayerPayloadBuf = Buffer.from(signatureLayerPayloadStr);
    const signatureContentInfo = builder.importString(signatureLayerPayloadStr);
    const signature = sha256.sign(signatureLayerPayloadBuf, options.key);

    const signatureConfig = {
      "architecture": "",
      "os": "",
      "rootfs": {
        "type": "layers",
        "diff_ids": [
          signatureContentInfo.digest
        ]
      }
    };
    const signatureConfigInfo = builder.importObject(signatureConfig);

    // https://github.com/rdkcentral/oci-package-spec/blob/main/format.md#signature-manifest
    const signatureManifest = {
      "schemaVersion": 2,
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "config": {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": signatureConfigInfo.digest,
        "size": signatureConfigInfo.size,
      },
      "layers": [
        {
          "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
          "digest": signatureContentInfo.digest,
          "size": signatureContentInfo.size,
          "annotations": {
            "dev.cosignproject.cosign/signature": signature,
          }
        }
      ]
    };

    if (options.cert) {
      if (!sha256.verify(signatureLayerPayloadBuf, options.cert, signature)) {
        throw new Error(`Certificate ${options.cert} does not match key ${options.key}!`);
      }
      signatureManifest.layers[0].annotations["dev.sigstore.cosign/certificate"] = readFileSync(options.cert, 'utf-8');
    }

    const signatureManifestInfo = builder.importObject(signatureManifest);

    // https://github.com/rdkcentral/oci-package-spec/blob/main/format.md#index-indexjson
    index.manifests.push({
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": signatureManifestInfo.digest,
      "size": signatureManifestInfo.size,
      "annotations": {
        "org.opencontainers.image.ref.name": `${manifestInfo.digest.replace(':', '-')}.sig`
      }
    });
  }
  builder.addString('index.json', JSON.stringify(index, null, 2));
  builder.addString('oci-layout', '{"imageLayoutVersion": "1.0.0"}');
  const packageFile = builder.close();

  if (useRalfpack) {
    ralfpackSign(packageFile, options);
  }
}

exports.pack = pack;
exports.writeOCIIndex = writeOCIIndex;

exports.packOptions = {
  key: commonOptions.key,
  cert: commonOptions.cert,
}

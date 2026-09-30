/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
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

const { ZIP } = require('./tools/ZIP.cjs');
const sha256 = require('./tools/sha256.cjs');
const { moveSync } = require('./utils.cjs');
const { statSync, rmSync } = require('node:fs');
const path = require('node:path');

const IMPORTED_FILES_ALIGNMENT = 4096;

class ZIPPackageBuilder {
  constructor(outputFile, workDir) {
    this.outputFile = outputFile;
    rmSync(outputFile, { recursive: true, force: true });
    this.zip = new ZIP(path.join(workDir, path.basename(outputFile) + '~'));
  }

  importFile(inputFile) {
    const {inputFileDigest, inputFileSize} = this.getFileManifestData(inputFile)
    this.zip.addFile('blobs/sha256/' + inputFileDigest, inputFile, IMPORTED_FILES_ALIGNMENT);
    return this.formatFileManifestData({inputFileDigest, inputFileSize});
  }

  getFileManifestData(inputFile) {
    return {
      inputFileDigest : sha256.hashFile(inputFile),
      inputFileSize : statSync(inputFile).size
    }
  }

  formatFileManifestData({inputFileDigest, inputFileSize}) {
    return {
      digest: 'sha256:' + inputFileDigest,
      size: inputFileSize
    };
  }

  importString(str) {
    const buf = Buffer.from(str);
    const digest = sha256.hash(buf);
    this.zip.add('blobs/sha256/' + digest, buf);

    return {
      digest: 'sha256:' + digest,
      size: buf.length,
    }
  }

  importObject(obj) {
    return this.importString(JSON.stringify(obj, null, 2));
  }

  getObjectManifestData(obj) {
    const buf = Buffer.from(JSON.stringify(obj, null, 2));
    return {
      digest: 'sha256:' + sha256.hash(buf),
      size: buf.length,
    }
  }

  addString(name, str) {
    this.zip.addString(name, str);
  }

  close() {
    moveSync(this.zip.close(), this.outputFile);
    return this.outputFile;
  }
};

exports.ZIPPackageBuilder = ZIPPackageBuilder;

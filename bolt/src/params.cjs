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

function parse() {
  const result = {
    args: [],
    options: {}
  };

  process.argv.slice(2).forEach(value => {
    if (value.startsWith("--")) {
      const option = value.substring(2).split("=");
      let optionName = option.shift();
      let optionValue = option.join("=");
      if (result.options[optionName] && !Array.isArray(result.options[optionName])) {
        result.options[optionName] = [result.options[optionName]]
      }
      if (Array.isArray(result.options[optionName])) {
        result.options[optionName].push(optionValue);
      } else {
        result.options[optionName] = optionValue;
      }
    } else {
      result.args.push(value);
    }
  });

  return result;
}

module.exports = parse();

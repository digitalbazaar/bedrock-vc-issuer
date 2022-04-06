/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {createRequire} from 'module';
const require = createRequire(import.meta.url);
const {generateId} = require('bnid');
const vc = require('@digitalbazaar/vc');

export async function generateLocalId() {
  // 128-bit random number, base58 multibase + multihash encoded
  return generateId({
    bitLength: 128,
    encoding: 'base58',
    multibase: true,
    multihash: true
  });
}

// helpers must export this function and not `issuer` to prevent circular
// dependencies via `CredentialStatusWriter`, `ListManager` and `issuer`
export async function issue({credential, documentLoader, suite}) {
  // vc-js.issue may be fixed to not mutate credential
  // see: https://github.com/digitalbazaar/vc-js/issues/76
  credential = {...credential};
  return vc.issue({credential, documentLoader, suite});
}

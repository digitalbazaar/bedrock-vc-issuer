/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {createRequire} from 'node:module';
const require = createRequire(import.meta.url);
const {generateId} = require('bnid');
const vc = require('@digitalbazaar/vc');
const {getCredentialStatus} = require('@digitalbazaar/vc-status-list');
const {
  getCredentialStatus: get2020CredentialStatus
} = require('vc-revocation-list');

export async function generateLocalId() {
  // 128-bit random number, base58 multibase + multihash encoded
  return generateId({
    bitLength: 128,
    encoding: 'base58',
    multibase: true,
    multihash: true
  });
}

export function getCredentialStatusInfo({credential, statusListConfig}) {
  const {type, statusPurpose} = statusListConfig;
  let credentialStatus;
  let statusListIndex;
  let statusListCredential;
  if(type === 'RevocationList2020') {
    // use legacy credential status
    credentialStatus = get2020CredentialStatus({credential});
    statusListIndex = parseInt(credentialStatus.revocationListIndex, 10);
    ({revocationListCredential: statusListCredential} = credentialStatus);
  } else {
    // use modern status list (2021)
    credentialStatus = getCredentialStatus({credential, statusPurpose});
    statusListIndex = parseInt(credentialStatus.statusListIndex, 10);
    ({statusListCredential} = credentialStatus);
  }
  return {credentialStatus, statusListIndex, statusListCredential};
}

// helpers must export this function and not `issuer` to prevent circular
// dependencies via `CredentialStatusWriter`, `ListManager` and `issuer`
export async function issue({credential, documentLoader, suite}) {
  // vc-js.issue may be fixed to not mutate credential
  // see: https://github.com/digitalbazaar/vc-js/issues/76
  credential = {...credential};
  return vc.issue({credential, documentLoader, suite});
}

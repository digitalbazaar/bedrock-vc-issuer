/*!
 * Copyright (c) 2020-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as vc from '@digitalbazaar/vc';
import {generateId} from 'bnid';
import {
  getCredentialStatus as get2020CredentialStatus
} from '@digitalbazaar/vc-revocation-list';
import {getCredentialStatus} from '@digitalbazaar/vc-status-list';

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

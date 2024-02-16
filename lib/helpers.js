/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as vc from '@digitalbazaar/vc';
import {AsymmetricKey, KmsClient} from '@digitalbazaar/webkms-client';
import {didIo} from '@bedrock/did-io';
import {generateId} from 'bnid';
import {
  getCredentialStatus as get2020CredentialStatus
} from '@digitalbazaar/vc-revocation-list';
import {getCredentialStatus} from '@digitalbazaar/vc-status-list';
import {getSuiteParams} from './suites.js';
import {httpsAgent} from '@bedrock/https-agent';
import {serviceAgents} from '@bedrock/service-agent';
import {serviceType} from './constants.js';

const {util: {BedrockError}} = bedrock;

export async function generateLocalId() {
  // 128-bit random number, base58 multibase + multihash encoded
  return generateId({
    bitLength: 128,
    encoding: 'base58',
    multibase: true,
    multihash: true
  });
}

// FIXME: move elsewhere?
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
  // FIXME: support other `credentialStatus` types
  return {credentialStatus, statusListIndex, statusListCredential};
}

export async function getIssuerAndSuite({
  config, suiteName = config.issueOptions.suiteName
}) {
  // get suite params for issuing a VC
  const {createSuite, referenceId} = getSuiteParams({config, suiteName});

  // get assertion method key to use for signing VCs
  const {serviceAgent} = await serviceAgents.get({serviceType});
  const {
    capabilityAgent, zcaps
  } = await serviceAgents.getEphemeralAgent({config, serviceAgent});
  const invocationSigner = capabilityAgent.getSigner();
  const zcap = zcaps[referenceId];
  const kmsClient = new KmsClient({httpsAgent});
  const assertionMethodKey = await AsymmetricKey.fromCapability(
    {capability: zcap, invocationSigner, kmsClient});

  // get `issuer` ID by getting key's public controller
  let issuer;
  try {
    const {controller} = await didIo.get({url: assertionMethodKey.id});
    issuer = controller;
  } catch(e) {
    throw new BedrockError(
      'Unable to determine credential issuer.', 'AbortError', {
        httpStatusCode: 400,
        public: true
      }, e);
  }
  const suite = createSuite({signer: assertionMethodKey});
  return {issuer, suite};
}

// helpers must export this function and not `issuer` to prevent circular
// dependencies via `CredentialStatusWriter`, `ListManager` and `issuer`
export async function issue({credential, documentLoader, suite}) {
  // vc-js.issue may be fixed to not mutate credential
  // see: https://github.com/digitalbazaar/vc-js/issues/76
  credential = {...credential};
  return vc.issue({credential, documentLoader, suite});
}

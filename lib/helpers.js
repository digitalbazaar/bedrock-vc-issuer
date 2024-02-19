/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as vc from '@digitalbazaar/vc';
import {AsymmetricKey, KmsClient} from '@digitalbazaar/webkms-client';
import {didIo} from '@bedrock/did-io';
import {documentStores} from '@bedrock/service-agent';
import {generateId} from 'bnid';
import {getSuiteParams} from './suites.js';
import {httpsAgent} from '@bedrock/https-agent';
import {serviceAgents} from '@bedrock/service-agent';
import {serviceType} from './constants.js';

const {util: {BedrockError}} = bedrock;

export function assertSlcDoc({slcDoc, id} = {}) {
  if(!(slcDoc?.meta.type === 'VerifiableCredential' &&
    _isStatusListCredential({credential: slcDoc?.content}))) {
    throw new BedrockError(
      `Credential "${id}" is not a supported status list credential.`, {
        name: 'DataError',
        details: {
          httpStatusCode: 400,
          public: true
        }
      });
  }
}

export async function generateLocalId() {
  // 128-bit random number, base58 multibase + multihash encoded
  return generateId({
    bitLength: 128,
    encoding: 'base58',
    multibase: true,
    multihash: true
  });
}

export async function getDocumentStore({config}) {
  // ensure indexes are set for VCs
  const {documentStore} = await documentStores.get({config, serviceType});
  const {edvClient} = documentStore;
  // use `meta.credentialStatus.id` field as some credentials may not include
  // the ID directly
  edvClient.ensureIndex({
    attribute: ['meta.credentialStatus.id'],
    unique: true
  });
  return documentStore;
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
  } catch(cause) {
    throw new BedrockError(
      'Unable to determine credential issuer.', {
        name: 'AbortError',
        details: {
          httpStatusCode: 400,
          public: true
        },
        cause
      });
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

// check if `credential` is some known type of status list credential
function _isStatusListCredential({credential}) {
  // FIXME: check for VC context as well
  if(!(credential['@context'] && Array.isArray(credential['@context']))) {
    return false;
  }
  if(!(credential.type && Array.isArray(credential.type) &&
    credential.type.includes('VerifiableCredential'))) {
    return false;
  }

  for(const type of credential.type) {
    if(type === 'RevocationList2020Credential') {
      // FIXME: check for matching `@context` as well
      return true;
    }
    if(type === 'StatusList2021Credential') {
      // FIXME: check for matching `@context as well
      return true;
    }
  }
  // FIXME: check other types

  return false;
}

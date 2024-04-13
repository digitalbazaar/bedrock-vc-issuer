/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as vc from '@digitalbazaar/vc';
import {AsymmetricKey, KmsClient} from '@digitalbazaar/webkms-client';
import {didIo} from '@bedrock/did-io';
import {documentStores} from '@bedrock/service-agent';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {generateId} from 'bnid';
import {getSuiteParams} from './suites.js';
import {httpsAgent} from '@bedrock/https-agent';
import {serviceAgents} from '@bedrock/service-agent';
import {serviceType} from './constants.js';
import {ZcapClient} from '@digitalbazaar/ezcap';

const {util: {BedrockError}} = bedrock;

export function createZcapClient({capabilityAgent}) {
  const invocationSigner = capabilityAgent.getSigner();
  return new ZcapClient({
    agent: httpsAgent,
    invocationSigner,
    SuiteClass: Ed25519Signature2020
  });
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
  // use `meta.credentialId` to prevent duplicate credential reference IDs
  edvClient.ensureIndex({
    attribute: ['meta.credentialId'],
    unique: true
  });
  // use `meta.credentialStatus.id` field to prevent duplicate status entries
  edvClient.ensureIndex({
    attribute: ['meta.credentialStatus.id'],
    unique: true
  });
  return documentStore;
}

export async function getIssuerAndSuite({
  config, suiteName = config.issueOptions.suiteName, options
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
  const suite = await createSuite({
    signer: assertionMethodKey, config, options
  });
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

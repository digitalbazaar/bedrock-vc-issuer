/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {AsymmetricKey, KmsClient} from '@digitalbazaar/webkms-client';
import {didIo} from '@bedrock/did-io';
import {documentStores} from '@bedrock/service-agent';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {generateId} from 'bnid';
import {getEnvelopeParams} from './envelopes.js';
import {getSuiteParams} from './suites.js';
import {httpsAgent} from '@bedrock/https-agent';
import {logger} from './logger.js';
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

export async function getIssuerAndSecuringMethods({config, options}) {
  // get each suite's params for issuing a VC
  let issuer;
  let params;
  let legacy = false;
  const {issueOptions} = config;
  if(issueOptions.suiteName) {
    // legacy mode
    legacy = true;
    params = [
      getSuiteParams({config, suiteName: issueOptions.suiteName})
    ];
  } else {
    // modern
    ({issuer} = issueOptions);
    params = issueOptions.cryptosuites?.map(
      cryptosuite => getSuiteParams({config, cryptosuite})) || [];
    const {envelope} = issueOptions;
    if(envelope) {
      params.push(getEnvelopeParams({config, envelope}));
    }
  }

  // get assertion method key to use with each suite and ensure suites are
  // created in deterministic order by attaching suite instances to `params`
  const {serviceAgent} = await serviceAgents.get({serviceType});
  const {
    capabilityAgent, zcaps
  } = await serviceAgents.getEphemeralAgent({config, serviceAgent});
  const invocationSigner = capabilityAgent.getSigner();
  const kmsClient = new KmsClient({httpsAgent});
  let enveloper;
  await Promise.all(params.map(async p => {
    const zcap = zcaps[p.referenceId];
    try {
      p.assertionMethodKey = await AsymmetricKey.fromCapability({
        capability: zcap, invocationSigner, kmsClient
      });
      p.suite = await p.createSuite?.({
        signer: p.assertionMethodKey, config, options,
        cryptosuiteConfig: p.cryptosuite
      });
      // only one enveloper possible
      enveloper = p.enveloper = await p.createEnveloper?.({
        signer: p.assertionMethodKey, config, options,
        envelopeConfig: p.envelope
      });
    } catch(cause) {
      const error = new BedrockError(
        'Unable to create cryptosuite suite for issuance: ' + cause.message, {
          name: 'AbortError',
          details: {
            httpStatusCode: 500,
            public: true
          },
          cause
        });
      logger.error(error.message, {error});
      throw error;
    }
  }));

  if(legacy) {
    // in legacy mode, get `issuer` ID by getting key's public controller
    try {
      const [{assertionMethodKey}] = params;
      const {controller} = await didIo.get({url: assertionMethodKey.id});
      issuer = controller;
    } catch(cause) {
      throw new BedrockError(
        'Unable to determine credential issuer.', {
          name: 'AbortError',
          details: {
            httpStatusCode: 500,
            public: true
          },
          cause
        });
    }
  }

  const suites = params.filter(({suite}) => !!suite).map(({suite}) => suite);
  return {issuer, suites, enveloper};
}

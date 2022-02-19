/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {AsymmetricKey, KmsClient} from '@digitalbazaar/webkms-client';
import bedrock from 'bedrock';
import {didIo} from 'bedrock-did-io';
import {documentLoader} from './documentLoader.js';
import {documentStores, serviceAgents} from 'bedrock-service-agent';
import {Ed25519Signature2018} from '@digitalbazaar/ed25519-signature-2018';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {generateId} from 'bnid';
import {httpsAgent} from 'bedrock-https-agent';
import vc from '@digitalbazaar/vc';

const {util: {BedrockError}} = bedrock;

const serviceType = 'vc-issuer';

const SUPPORTED_SUITES = new Map([
  ['Ed25519Signature2020', {
    keyType: 'ed25519', SuiteClass: Ed25519Signature2020
  }],
  ['Ed25519Signature2018', {
    keyType: 'ed25519', SuiteClass: Ed25519Signature2018
  }]
]);

export async function generateLocalId() {
  // 128-bit random number, base58 multibase + multihash encoded
  return generateId({
    bitLength: 128,
    encoding: 'base58',
    multibase: true,
    multihash: true
  });
}

export async function issue({credential, suite}) {
  // vc-js.issue may be fixed to not mutate credential
  // see: https://github.com/digitalbazaar/vc-js/issues/76
  credential = {...credential};
  return vc.issue({credential, documentLoader, suite});
}

export async function getIssuingInterfaces({config, suiteName}) {
  // ensure suite is supported
  const suiteInfo = SUPPORTED_SUITES.get(suiteName);
  if(!suiteInfo) {
    throw new Error(`Unsupported suite "${suiteName}".`);
  }

  // get zcap to use to invoke assertion method key
  const {keyType, SuiteClass} = suiteInfo;
  const referenceId = `assertionMethod:${keyType}`;
  const zcap = config.zcaps[referenceId];
  if(!zcap) {
    throw new Error(
      `No capability available to sign using suite "${suiteName}".`);
  }

  // get assertion method key to use for signing VCs
  const {serviceAgent} = await serviceAgents.get({serviceType});
  const invocationSigner = await serviceAgents.get({serviceAgent});
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

  // create suite for signing
  const suite = new SuiteClass({signer: assertionMethodKey});

  // ensure indexes are set for VCs
  const documentStore = await documentStores.get({config, serviceType});
  const {edvClient} = documentStore;
  // FIXME: update as needed to work with status list 2021
  edvClient.ensureIndex({attribute: 'meta.revoked'});
  edvClient.ensureIndex({
    attribute: [
      'content.credentialStatus.id',
      'content.credentialStatus.revocationListIndex'
    ],
    unique: true
  });

  return {issuer, suite, documentStore};
};

/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brHttpsAgent = require('bedrock-https-agent');
const {
  AsymmetricKey,
  KeyAgreementKey,
  KeystoreAgent,
  KmsClient,
} = require('webkms-client');

// load config defaults
require('./config');

exports.createAsymmetricKey = ({invocationSigner, zcap}) => {
  const {httpsAgent} = brHttpsAgent;
  return new AsymmetricKey({
    // FIXME: is it necessary to specify id and type as with KeyAgreementKey?
    capability: zcap,
    invocationSigner,
    kmsClient: new KmsClient({httpsAgent}),
  });
};

exports.createKak = ({invocationSigner, zcap}) => {
  const {httpsAgent} = brHttpsAgent;
  return new KeyAgreementKey({
    id: zcap.invocationTarget.id,
    type: zcap.invocationTarget.type,
    capability: zcap,
    invocationSigner,
    kmsClient: new KmsClient({httpsAgent}),
  });
};

exports.createKeystore = async ({capabilityAgent, referenceId} = {}) => {
  const kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`;

  // create keystore
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    // TODO: add `invoker` and `delegator` using arrays including
    // capabilityAgent.id *and* identifier for backup key recovery entity
    invoker: capabilityAgent.id,
    delegator: capabilityAgent.id
  };
  if(referenceId) {
    config.referenceId = referenceId;
  }

  const {httpsAgent} = brHttpsAgent;
  return await KmsClient.createKeystore({
    url: `${kmsBaseUrl}/keystores`,
    config,
    httpsAgent
  });
};

exports.ensureKeystore = async ({capabilityAgent}) => {
  const kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`;

  const {httpsAgent} = brHttpsAgent;
  let config = await KmsClient.findKeystore({
    url: `${kmsBaseUrl}/keystores`,
    controller: capabilityAgent.id,
    referenceId: 'primary',
    httpsAgent
  });
  if(config === null) {
    config = await exports.createKeystore(
      {capabilityAgent, referenceId: 'primary'});
  }
  if(config === null) {
    return null;
  }
  const kmsClient = new KmsClient({httpsAgent});
  return new KeystoreAgent({keystore: config, capabilityAgent, kmsClient});
};

/*
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {didIo} = require('bedrock-did-io');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const {EdvClient} = require('@digitalbazaar/edv-client');
const {httpClient} = require('@digitalbazaar/http-client');
const {KeystoreAgent, KmsClient} = require('@digitalbazaar/webkms-client');
const {getAppIdentity} = require('bedrock-app-identity');
const {httpsAgent} = require('bedrock-https-agent');
const {ZcapClient} = require('@digitalbazaar/ezcap');

const mockData = require('./mock.data');

const edvBaseUrl = `${mockData.baseUrl}/edvs`;
const kmsBaseUrl = `${mockData.baseUrl}/kms`;

exports.createMeter = async ({capabilityAgent, serviceType} = {}) => {
  // create signer using the application's capability invocation key
  const {keys: {capabilityInvocationKey}} = getAppIdentity();

  const zcapClient = new ZcapClient({
    agent: httpsAgent,
    invocationSigner: capabilityInvocationKey.signer(),
    SuiteClass: Ed25519Signature2020
  });

  // create a meter
  const meterService = `${bedrock.config.server.baseUri}/meters`;
  let meter = {
    controller: capabilityAgent.id,
    product: {
      // mock ID for service type
      id: mockData.productIdMap.get(serviceType)
    }
  };
  ({data: {meter}} = await zcapClient.write({url: meterService, json: meter}));

  // return full meter ID
  const {id} = meter;
  return {id: `${meterService}/${id}`};
};

exports.createConfig = async ({
  capabilityAgent, ipAllowList, meterId, zcaps
} = {}) => {
  if(!meterId) {
    // create a meter for the keystore
    ({id: meterId} = await exports.createMeter({
      capabilityAgent, serviceType: 'vc-verifier'
    }));
  }

  // create service object
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    meterId
  };
  if(ipAllowList) {
    config.ipAllowList = ipAllowList;
  }
  if(zcaps) {
    config.zcaps = zcaps;
  }

  const zcapClient = exports.createZcapClient({capabilityAgent});
  const url = `${mockData.baseUrl}/verifiers`;
  const response = await zcapClient.write({url, json: config});
  return response.data;
};

exports.getConfig = async ({id, capabilityAgent}) => {
  const zcapClient = exports.createZcapClient({capabilityAgent});
  const {data} = await zcapClient.read({url: id});
  return data;
};

exports.createChallenge = async ({
  capabilityAgent, capability, verifierId
}) => {
  const zcapClient = exports.createZcapClient({capabilityAgent});
  return zcapClient.write({
    url: `${verifierId}/challenges`,
    capability: capability ||
      `urn:zcap:root:${encodeURIComponent(verifierId)}`,
    json: {}
  });
};

exports.createEdv = async ({
  capabilityAgent, keystoreAgent, keyAgreementKey, hmac, meterId
}) => {
  if(!meterId) {
    // create a meter for the keystore
    ({id: meterId} = await exports.createMeter({
      capabilityAgent, serviceType: 'edv'
    }));
  }

  if(!(keyAgreementKey && hmac) && keystoreAgent) {
    // create KAK and HMAC keys for edv config
    ([keyAgreementKey, hmac] = await Promise.all([
      keystoreAgent.generateKey({type: 'keyAgreement'}),
      keystoreAgent.generateKey({type: 'hmac'})
    ]));
  }

  // create edv
  const newEdvConfig = {
    sequence: 0,
    controller: capabilityAgent.id,
    keyAgreementKey: {id: keyAgreementKey.id, type: keyAgreementKey.type},
    hmac: {id: hmac.id, type: hmac.type},
    meterId
  };

  const edvConfig = await EdvClient.createEdv({
    config: newEdvConfig,
    httpsAgent,
    invocationSigner: capabilityAgent.getSigner(),
    url: edvBaseUrl
  });

  const edvClient = new EdvClient({
    id: edvConfig.id,
    keyResolver,
    keyAgreementKey,
    hmac,
    httpsAgent
  });

  return {edvClient, edvConfig, hmac, keyAgreementKey};
};

exports.createKeystore = async ({
  capabilityAgent, ipAllowList, meterId,
  kmsModule = 'ssm-v1'
}) => {
  if(!meterId) {
    // create a meter for the keystore
    ({id: meterId} = await exports.createMeter(
      {capabilityAgent, serviceType: 'webkms'}));
  }

  // create keystore
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    meterId,
    kmsModule
  };
  if(ipAllowList) {
    config.ipAllowList = ipAllowList;
  }

  return KmsClient.createKeystore({
    url: `${kmsBaseUrl}/keystores`,
    config,
    invocationSigner: capabilityAgent.getSigner(),
    httpsAgent
  });
};

exports.createKeystoreAgent = async ({capabilityAgent, ipAllowList}) => {
  let err;
  let keystore;
  try {
    keystore = await exports.createKeystore({capabilityAgent, ipAllowList});
  } catch(e) {
    err = e;
  }
  assertNoError(err);

  // create kmsClient only required because we need to use httpsAgent
  // that accepts self-signed certs used in test suite
  const kmsClient = new KmsClient({httpsAgent});
  const keystoreAgent = new KeystoreAgent({
    capabilityAgent,
    keystoreId: keystore.id,
    kmsClient
  });

  return keystoreAgent;
};

exports.createZcapClient = ({
  capabilityAgent, delegationSigner, invocationSigner
}) => {
  const signer = capabilityAgent && capabilityAgent.getSigner();
  return new ZcapClient({
    agent: httpsAgent,
    invocationSigner: invocationSigner || signer,
    delegationSigner: delegationSigner || signer,
    SuiteClass: Ed25519Signature2020
  });
};

exports.delegate = async ({
  capability, controller, invocationTarget, expires, allowedActions,
  delegator
}) => {
  const zcapClient = exports.createZcapClient({capabilityAgent: delegator});
  expires = expires || (capability && capability.expires) ||
    new Date(Date.now() + 5000).toISOString().slice(0, -5) + 'Z';
  return zcapClient.delegate({
    capability, controller, expires, invocationTarget, allowedActions
  });
};

exports.revokeDelegatedCapability = async ({
  serviceObjectId, capabilityToRevoke, invocationSigner
}) => {
  const url = `${serviceObjectId}/revocations/` +
    encodeURIComponent(capabilityToRevoke.id);
  const zcapClient = exports.createZcapClient({invocationSigner});
  return zcapClient.write({url, json: capabilityToRevoke});
};

async function keyResolver({id}) {
  // support DID-based keys only
  if(id.startsWith('did:')) {
    return didIo.get({url: id});
  }
  // support HTTP-based keys; currently a requirement for WebKMS
  const {data} = await httpClient.get(id, {agent: httpsAgent});
  return data;
}

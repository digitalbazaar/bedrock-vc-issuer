/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {CapabilityDelegation} = require('ocapld');
const {Ed25519Signature2018} = suites;
const {EdvClient} = require('edv-client');
const jsigs = require('jsonld-signatures');
const {SECURITY_CONTEXT_V2_URL, sign, suites} = jsigs;
const {util: {BedrockError}} = require('bedrock');

// load config defaults
require('./config');

const ALLOWED_ACTIONS = {
  read: 'read',
  write: ['read', 'write'],
  issue: ['sign']
};

// delegates zcaps to the given invoker/delegator for the given instance
exports.delegateCapabilities = async ({
  instance, signer, invoker, delegator, zcapMap
}) => {
  const controllerKey = await exports.getControllerKey({id: instance.id});
  const signer = await controllerKey.getAsymmetricKey(instance.keys.zcapKey);

  // check zcapMap's source zcaps to ensure they are valid
  const results = {};
  for(const type in zcapMap) {
    const {source, parent} = zcapMap[type];
    if(source !== parent) {
      // TODO: verify source has been delegated by parent and matches `type`
      // before simply rejecting
      throw new BedrockError(
        'Could not delegate capabilities.',
        'NotAllowedError',
        {httpStatusCode: 400, public: true});
    }
    // delegate zcap
    const zcap = {
      '@context': SECURITY_CONTEXT_V2_URL,
      // use 128-bit random multibase encoded value
      id: `urn:zcap:${await EdvClient.generateId()}`,
      parentCapability: parent,
      invoker,
      delegator,
      referenceId: parent.referenceId,
      allowedAction: ALLOWED_ACTIONS[type],
      invocationTarget: {...parent.invocationTarget}
    };
    const delegated = await _delegate({zcap, signer});
    results[delegated.referenceId] = delegated;
  }
  return results;
};

async function _delegate({zcap, signer}) {
  // attach capability delegation proof
  return sign(zcap, {
    // TODO: map `signer.type` to signature suite
    suite: new Ed25519Signature2018({
      signer,
      verificationMethod: signer.id
    }),
    purpose: new CapabilityDelegation({
      capabilityChain: [zcap.parentCapability]
    }),
    compactProof: false
  });
}

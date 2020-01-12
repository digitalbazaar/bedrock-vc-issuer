/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// FIXME: use `base58-universal` instead
const base58 = require('bs58');
const brZCapStorage = require('bedrock-zcap-storage');
const database = require('bedrock-mongodb');
const {CapabilityDelegation} = require('ocapld');
const {EdvClient} = require('edv-client');
const jsigs = require('jsonld-signatures');
const {extendContextLoader, SECURITY_CONTEXT_V2_URL, sign, suites} = jsigs;
const {Ed25519Signature2018} = suites;
const {util: {BedrockError}} = require('bedrock');

// load config defaults
require('./config');

const ALLOWED_ACTIONS = {
  read: ['read'],
  write: ['read', 'write'],
  issue: ['sign'],
  kak: ['deriveSecret'],
  hmac: ['sign', 'verify']
};

// delegates zcaps to the given invoker/delegator for the given instance
exports.delegateCapabilities = async ({
  instance, controllerKey, invoker, delegator, zcapMap
}) => {
  const signer = await controllerKey.getAsymmetricKey(instance.keys.zcapKey);

  // delegate each type in `zcapMap`
  const results = {};
  for(const type in zcapMap) {
    const parent = zcapMap[type];
    // delegate zcap
    let delegated;
    const zcap = {
      '@context': SECURITY_CONTEXT_V2_URL,
      // use 128-bit random multibase encoded value
      id: `urn:zcap:${await EdvClient.generateId()}`,
      parentCapability: parent.id,
      invoker,
      delegator,
      // FIXME: ensure ocapld.js checks allowedActions when verifying
      // delegation chains
      allowedAction: ALLOWED_ACTIONS[type]
    };
    if(type === 'kak' || type === 'hmac') {
      zcap.referenceId = `${instance.id}-${type}`;
      zcap.invocationTarget = {
        id: parent.id,
        type: parent.type
      };
      // delegate via controller key directly since it is the `controller`
      // of the `kak` and the `hmac`
      // FIXME: consider making zcap key `did:key` the controller instead
      delegated = await _delegate({zcap, signer: controllerKey});
    } else {
      zcap.referenceId = parent.referenceId;
      zcap.invocationTarget = {...parent.invocationTarget};
      // delegate via externally referenced zcap key
      delegated = await _delegate({zcap, signer});
    }
    results[delegated.referenceId] = delegated;
  }
  return results;
};

// FIXME: use did-key lib instead
// Note: for dereferencing `did:key` URLs
const DOCUMENT_LOADER = async url => {
  if(url.startsWith('did:key:')) {
    const publicKeyBase58 = _parsePublicKeyBase58(url);
    return {
      contextUrl: null,
      documentUrl: url,
      document: {
        '@context': SECURITY_CONTEXT_V2_URL,
        id: url,
        publicKey: [{
          id: url,
          // TODO: determine from parsing multibase key
          type: 'Ed25519VerificationKey2018',
          controller: url,
          publicKeyBase58
        }],
        authentication: [url],
        assertionMethod: [url],
        capabilityDelegation: [url],
        capabilityInvocation: [url]
      }
    };
  }
  const error = new Error(`Dereferencing url "${url}" is prohibited.`);
  error.name = 'NotAllowedError';
  error.httpStatusCode = 400;
  throw error;
};

function _parsePublicKeyBase58(didKeyUrl) {
  const fingerprint = didKeyUrl.substr('did:key:'.length);
  // skip leading `z` that indicates base58 encoding
  const buffer = base58.decode(fingerprint.substr(1));
  // assume buffer is: 0xed 0x01 <public key bytes>
  return base58.encode(buffer.slice(2));
}

exports.verifyPartialDelegation = async ({
  controllerKey, instance, capability
}) => {
  // determine the instance's core capability in the chain
  let core;
  let invocationTarget;
  let controller;
  // FIXME: brittle; refactor to make more robust... security also depends
  // on where this function is called from as it relies on reference IDs here
  const {referenceId} = capability;
  if(referenceId.includes('-edv-') || referenceId.includes('-key-')) {
    core = await instance.zcaps.find(c => c.referenceId === referenceId);
    if(!core) {
      throw new BedrockError(
        'Invalid delegated credential; reference ID does not match.',
        'InvalidStateError', {
          capability: capability.id,
          referenceId,
          httpStatusCode: 500, public: true
        });
    }
    invocationTarget = typeof core.invocationTarget === 'string' ?
      core.invocationTarget : core.invocationTarget.id;
    controller = instance.keys.zcapKey.id;
  } else {
    invocationTarget = typeof capability.invocationTarget === 'string' ?
      capability.invocationTarget : capability.invocationTarget.id;
    controller = controllerKey.id;
  }

  // create a fake root capability as a terminating zcap for the verification
  // process as the instance's core capability
  const terminal = {
    '@context': SECURITY_CONTEXT_V2_URL,
    id: invocationTarget,
    controller
  };

  const documentLoader = extendContextLoader(async url => {
    if(url.startsWith('did:key:')) {
      return DOCUMENT_LOADER(url);
    }

    // use core expected zcap
    if(core && url === core.id) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: core
      };
    }

    // use terminal zcap
    if(url === terminal.id) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: terminal
      };
    }

    // check zcap storage for zcap controlled by the delegating account
    const [record] = await brZCapStorage.zcaps.find({
      query: {id: database.hash(url)},
      fields: {_id: 0, capability: 1},
      options: {limit: 1}
    });
    if(record) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: record.capability
      };
    }

    return DOCUMENT_LOADER(url);
  });

  const {verified, error} = await jsigs.verify(capability, {
    suite: new Ed25519Signature2018(),
    purpose: new CapabilityDelegation({
      suite: new Ed25519Signature2018()
    }),
    documentLoader,
    compactProof: false
  });
  if(!verified) {
    throw error;
  }
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

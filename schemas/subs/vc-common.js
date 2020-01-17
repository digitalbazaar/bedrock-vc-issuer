/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const {schemas} = require('bedrock-validation');

const {constants} = config;

const proof = () => ({
  type: 'object',
  title: 'JSON LD Proof',
  required: [
    'type',
    'created',
    'proofPurpose',
    'verificationMethod',
    'jws'
  ],
  properties: {
    type: {type: 'string'},
    proofPurpose: {
      type: 'string',
      examples: [
        'authentication',
        'capabilityDelegation'
      ]
    },
    verificationMethod: {type: 'string'},
    created: schemas.w3cDateTime(),
    challenge: {type: 'string'},
    jws: {type: 'string'}
  }
});

// add the capabilitychain for the CapabilityDelegationProof.
const capabilityDelegationProof = () => {
  const _proof = proof();
  _proof.title = 'Capability Delegation Proof';
  _proof.required.push('capabilityChain');
  _proof.properties.capabilityChain = {
    type: 'array',
    items: {type: 'string'},
    minItems: 1
  };
  _proof.properties.proofPurpose.const = 'capabilityDelegation';
  return _proof;
};

const authenticationProof = () => {
  const _proof = proof();
  _proof.title = 'Authentication Proof';
  _proof.required.push('challenge');
  _proof.properties.challenge = {
    challenge: {type: 'string'}
  };
  _proof.properties.proofPurpose.const = 'authentication';
  return _proof;
};

const allowedActionString = {
  title: 'Allowed Action String',
  type: 'string'
};

const allowedActionArray = {
  title: 'Allowed Action Array',
  type: 'array',
  items: allowedActionString,
  minItems: 1
};

const delegationZCap = () => ({
  title: 'ZCap',
  type: 'object',
  required: [
    '@context',
    'invoker',
    'allowedAction',
    'invocationTarget',
    'proof'
  ],
  properties: {
    '@context': schemas.jsonldContext(constants.SECURITY_CONTEXT_V2_URL),
    id: {type: 'string'},
    invoker: {type: 'string'},
    delegator: {type: 'string'},
    referenceId: {type: 'string'},
    allowedAction: {
      title: 'Allowed Action',
      anyOf: [allowedActionArray, allowedActionString]
    },
    invocationTarget: {
      title: 'Invocation Target',
      type: 'object',
      required: ['id', 'type'],
      properties: {
        id: {type: 'string'},
        type: {type: 'string'}
      }
    },
    parentCapability: {type: 'string'},
    proof: capabilityDelegationProof(),
    jws: {type: 'string'}
  }
});

// used to Verify that the type of a presentation
// matches VerifiablePresentation exactly.
const verifiablePresentationType = () => ({
  title: 'Verifiable Presentation Type',
  type: 'string',
  const: 'VerifiablePresentation'
});

module.exports.verifiablePresentationType = verifiablePresentationType;
module.exports.delegationZCap = delegationZCap;
module.exports.capabilityDelegationProof = capabilityDelegationProof;
module.exports.authenticationProof = authenticationProof;
module.exports.proof = proof;

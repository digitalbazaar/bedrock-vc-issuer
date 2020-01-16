const {schemas} = require('bedrock-validation');

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
    proofPurpose: {type: 'string'},
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
  return _proof;
};

const allowedActionArray = {
  title: 'Allowed Action Array',
  type: 'array',
  items: {type: 'string'},
  minItems: 1
};

const allowedActionString = {
  title: 'Allowed Action String',
  type: 'string'
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
    '@context': schemas.jsonldContext(),
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

const authenticationProof = () => {
  const _proof = proof();
  _proof.title = 'Authentication Proof',
  _proof.required.push('challenge');
  _proof.properties.challenge = {
    challenge: {type: 'string'}
  };
  return _proof;
};

module.exports.delegationZCap = delegationZCap;
module.exports.capabilityDelegationProof = capabilityDelegationProof;
module.exports.authenticationProof = authenticationProof;
module.exports.proof = proof;

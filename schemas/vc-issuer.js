/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const {schemas} = require('bedrock-validation');
const {
  authenticationProof,
  verifiablePresentationType,
  delegationZCap
} = require('./subs/vc-common');

const {constants} = config;

const instancesQuery = {
  title: 'Instances Query',
  type: 'object',
  additionalProperties: false,
  required: ['controller'],
  $schema: 'http://json-schema.org/draft-07/schema#',
  properties: {
    controller: {type: 'string'},
  }
};

const instancesCreate = {
  title: 'Instances Create',
  type: 'object',
  additionalProperties: false,
  required: ['controller', 'id', 'name'],
  $schema: 'http://json-schema.org/draft-07/schema#',
  properties: {
    // urn:uuid:a99bfceb-f888-44f2-9319-d51e36038062
    controller: {type: 'string'},
    // uuid
    id: {type: 'string'},
    // user supplied string, human readable name of the instance
    name: {type: 'string'},
  }
};

const instancesUpdate = {
  title: 'Issuer Instance Update',
  type: 'object',
  required: ['controller', 'presentation'],
  $schema: 'http://json-schema.org/draft-07/schema#',
  properties: {
    controller: {
      type: 'string',
      title: 'The Update Controller',
      examples: [
        'urn:uuid:a99bfceb-f888-44f2-9319-d51e36038062'
      ],
      // FIXME add a regex for controller ids in veres-issuer
      pattern: '^(.*)$'
    },
    presentation: {
      title: 'Issuer Instance Presentation',
      type: 'object',
      required: [
        '@context',
        'type',
        'holder',
        'capability',
        'proof'
      ],
      properties: {
        '@context': schemas.jsonldContext(constants.CREDENTIALS_CONTEXT_V1_URL),
        type: verifiablePresentationType(),
        holder: {
          $id: '#/properties/presentation/properties/holder',
          type: 'string',
          title: 'The Holder Schema',
          examples: [
            'did:v1:test:nym:z6MkjrFvxZyHF6pNLqMynYSfL14oUkSPvENaqCUE2ygrtDNV'
          ],
          pattern: '^(.*)$'
        },
        capability: {
          type: 'array',
          title: 'Capability',
          items: delegationZCap()
        },
        proof: authenticationProof()
      }
    }
  }
};

const login = {
  type: 'object',
  title: 'DID Login',
  required: ['presentation'],
  $schema: 'http://json-schema.org/draft-07/schema#',
  properties: {
    presentation: {
      title: 'DID Login Presentation',
      type: 'object',
      required: ['@context', 'type', 'holder', 'proof'],
      properties: {
        '@context': schemas.jsonldContext(constants.CREDENTIALS_CONTEXT_V1_URL),
        type: verifiablePresentationType(),
        holder: {type: 'string'},
        proof: authenticationProof()
      }
    }
  }
};

const claimUser = {
  type: 'object',
  title: 'User Claim',
  additionalProperties: false,
  required: ['token', 'instanceId'],
  $schema: 'http://json-schema.org/draft-07/schema#',
  properties: {
    token: {
      type: 'string'
    },
    instanceId: {
      type: 'string'
    }
  }
};

const capabilitiesQuery = {
  title: 'Capabilities Query',
  type: 'object',
  additionalProperties: false,
  required: ['account'],
  $schema: 'http://json-schema.org/draft-07/schema#',
  properties: {
    account: {type: 'string'},
  }
};

exports.login = () => login;
exports.claimUser = () => claimUser;
exports.capabilitiesQuery = () => capabilitiesQuery;
module.exports.instancesUpdate = () => instancesUpdate;
module.exports.instancesCreate = () => instancesCreate;
module.exports.instancesQuery = () => instancesQuery;

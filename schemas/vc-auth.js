/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const {schemas} = require('bedrock-validation');
const {authenticationProof} = require('./subs/vc-common');

const {constants} = config;

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
        type: {type: 'string'},
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

exports.login = () => login;
exports.claimUser = () => claimUser;

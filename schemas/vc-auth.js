/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {schemas} = require('bedrock-validation');
const {authenticationProof} = require('./subs/vc-common');

const login = {
  type: 'object',
  title: 'DID Login',
  required: ['presentation'],
  properties: {
    presentation: {
      title: 'DID Login Presentation',
      type: 'object',
      required: ['@context', 'type', 'holder', 'proof'],
      properties: {
        '@context': schemas.jsonldContext(),
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

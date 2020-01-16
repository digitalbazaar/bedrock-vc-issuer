/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {schemas} = require('bedrock-validation');

/**
 *  DID AUTH REQ BODY workerPid=19432, details={
  "body": {
    "presentation": {
      "@context": "https://www.w3.org/2018/credentials/v1",
      "type": "VerifiablePresentation",
      "holder": "did:v1:test:nym:z6Mkm8ukp7U3Vnz5tengH9tNyUcR9FkkzhE7AXZuebdYsKbe",
      "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-06-18T21:19:10Z",
        "proofPurpose": "authentication",
        "verificationMethod": "did:v1:test:nym:z6Mkm8ukp7U3Vnz5tengH9tNyUcR9FkkzhE7AXZuebdYsKbe#key",
        "challenge": "fb990197-c8f9-4bf7-8313-e8abe4c94792",
        "jws": "BavEll0/I1..W3JT24="
      }
    }
  }
}
*/

const proof = () => ({
  type: 'object',
  title: 'Json Ld Proof',
  required: ['type', 'created', 'proofPurpose', 'verificationMethod', 'jws'],
  properties: {
    type: {type: 'string'},
    proofPurpose: {type: 'string'},
    verificationMethod: {type: 'string'},
    created: {type: 'string'},
    challenge: {type: 'string'},
    jws: {type: 'string'}
  }
});

const login = {
  type: 'object',
  title: 'DID Login',
  required: ['presentation'],
  properties: {
    presentation: {
      title: 'DID Login Presentation',
      type: 'object',
      required: ['@context', 'type', 'holder', 'proof'],
      additionalProperties: false,
      properties: {
        '@context': schemas.jsonldContext(),
        type: {
          type: 'string'
        },
        holder: {
          type: 'string'
        },
        proof: proof()
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

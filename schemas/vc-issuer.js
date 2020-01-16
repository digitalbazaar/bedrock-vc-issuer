/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {schemas} = require('bedrock-validation');
const {presentation} = require('./subs/presentation');
const {
  authenticationProof,
  delegationZCap
} = require('./subs/vc-common');

const instancesQuery = {
  title: 'Instances Query',
  type: 'object',
  additionalProperties: false,
  required: ['controller'],
  properties: {
    controller: {type: 'string'},
  }
};

const instancesCreate = {
  title: 'Instances Create',
  type: 'object',
  additionalProperties: false,
  required: ['controller', 'id', 'name'],
  properties: {
    // urn:uuid:a99bfceb-f888-44f2-9319-d51e36038062
    controller: {type: 'string'},
    // uuid
    id: {type: 'string'},
    // user supplied string, human readable name of the instance
    name: {type: 'string'},
  }
};

/**
CREATE ISSUER JSON {
  "controller": "urn:uuid:de79d915-791f-4bca-9d7d-ee878b5c3ea5",
  "presentation": {
    "@context": "https://www.w3.org/2018/credentials/v1",
    "type": "VerifiablePresentation",
    "holder": "did:v1:test:nym:z6Mkm8ukp7U3Vnz5tengH9tNyUcR9FkkzhE7AXZuebdYsKbe",
    "capability": [
      {
        "@context": "https://w3id.org/security/v2",
        "id": "urn:zcap:z19rhnRvuGmb8718ivL2WuysA",
        "invoker": "did:key:z6MksjyK6sEf39xPAxUVdYBGCuE6sfuAxqnpzbod4JBuoGqv",
        "delegator": "did:key:z6MksjyK6sEf39xPAxUVdYBGCuE6sfuAxqnpzbod4JBuoGqv",
        "referenceId": "d548b050-1fbc-4763-932c-1de0a85d3fa7-edv-authorizations",
        "allowedAction": [
          "read",
          "write"
        ],
        "invocationTarget": {
          "id": "https://localhost:38443/edvs/z1A9SL5HWmLqzZWaXyk3ECvaR/authorizations",
          "type": "urn:edv:authorizations"
        },
        "parentCapability": "https://localhost:38443/edvs/z1A9SL5HWmLqzZWaXyk3ECvaR/zcaps/authorizations",
        "proof": {
          "type": "Ed25519Signature2018",
          "created": "2020-01-15T21:39:45Z",
          "verificationMethod": "did:key:z6MkfFetqA1WKhxkvtLo6C7CKWsYz4f59BnVLFBcXFnxgkdR",
          "proofPurpose": "capabilityDelegation",
          "capabilityChain": [
            "https://localhost:38443/edvs/z1A9SL5HWmLqzZWaXyk3ECvaR/zcaps/authorizations"
          ],
          "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A0gICWINdcbuhTa-uqvfVpAln9HpcEtUDam9vJRarj31gE8PoZ9a0JdAGWQ-U7RuavpchxbXLXGLXoT-AuLDBQ"
        }
      },
      {
        "@context": "https://w3id.org/security/v2",
        "id": "urn:zcap:z19uQ7sLL3GR5PraGKpHGqhWC",
        "invoker": "did:key:z6MksjyK6sEf39xPAxUVdYBGCuE6sfuAxqnpzbod4JBuoGqv",
        "delegator": "did:key:z6MksjyK6sEf39xPAxUVdYBGCuE6sfuAxqnpzbod4JBuoGqv",
        "referenceId": "d548b050-1fbc-4763-932c-1de0a85d3fa7-key-assertionMethod",
        "allowedAction": "sign",
        "invocationTarget": {
          "id": "https://localhost:38443/kms/keystores/z19oyRXisoyXXfywbtF3kyUrq/keys/z1A5DMguC21HFbApXk2MgYt7D",
          "type": "Ed25519VerificationKey2018"
        },
        "parentCapability": "https://localhost:38443/kms/keystores/z19oyRXisoyXXfywbtF3kyUrq/keys/z1A5DMguC21HFbApXk2MgYt7D",
        "proof": {
          "type": "Ed25519Signature2018",
          "created": "2020-01-15T21:39:45Z",
          "verificationMethod": "did:key:z6MkfFetqA1WKhxkvtLo6C7CKWsYz4f59BnVLFBcXFnxgkdR",
          "proofPurpose": "capabilityDelegation",
          "capabilityChain": [
            "https://localhost:38443/kms/keystores/z19oyRXisoyXXfywbtF3kyUrq/keys/z1A5DMguC21HFbApXk2MgYt7D"
          ],
          "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..OxdqBrSsSGOUawO3O3jckW2JoIGV3S2igPnHY6dJJqbJJSsKvLoZiGBxcgHb_OcfJlWBC53-RPSpLS3_BvuaDg"
        }
      },
      {
        "@context": "https://w3id.org/security/v2",
        "id": "urn:zcap:z1A6RhCeEWxCSXSu3A7wtAST2",
        "invoker": "did:key:z6MksjyK6sEf39xPAxUVdYBGCuE6sfuAxqnpzbod4JBuoGqv",
        "delegator": "did:key:z6MksjyK6sEf39xPAxUVdYBGCuE6sfuAxqnpzbod4JBuoGqv",
        "referenceId": "d548b050-1fbc-4763-932c-1de0a85d3fa7-key-authorizations",
        "allowedAction": [
          "read",
          "write"
        ],
        "invocationTarget": {
          "id": "https://localhost:38443/kms/keystores/z19oyRXisoyXXfywbtF3kyUrq/authorizations",
          "type": "urn:webkms:authorizations"
        },
        "parentCapability": "https://localhost:38443/kms/keystores/z19oyRXisoyXXfywbtF3kyUrq/zcaps/authorizations",
        "proof": {
          "type": "Ed25519Signature2018",
          "created": "2020-01-15T21:39:45Z",
          "verificationMethod": "did:key:z6MkfFetqA1WKhxkvtLo6C7CKWsYz4f59BnVLFBcXFnxgkdR",
          "proofPurpose": "capabilityDelegation",
          "capabilityChain": [
            "https://localhost:38443/kms/keystores/z19oyRXisoyXXfywbtF3kyUrq/zcaps/authorizations"
          ],
          "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..1NW337KOhfUvEni3dQRz3E4NaZ_kUQ4o61Wqw60RoXBNLj7j7NdrJ3X92glq8R8Cy7Q_15B1adOZMek5Nho1Dg"
        }
      }
    ],
    "proof": {
      "type": "Ed25519Signature2018",
      "created": "2020-06-18T21:19:10Z",
      "proofPurpose": "authentication",
      "verificationMethod": "did:v1:test:nym:z6Mkm8ukp7U3Vnz5tengH9tNyUcR9FkkzhE7AXZuebdYsKbe#key",
      "challenge": "c0ae1c8e-c7e7-469f-b252-86e6a0e7387e",
      "jws": "BavEll0/I1..W3JT24="
    }
  }
}
*/

const instancesUpdate = {
  title: 'Issuer Instance Update',
  type: 'object',
  required: ['controller', 'presentation'],
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
        '@context': schemas.jsonldContext(),
        type: {
          $id: '#/properties/presentation/properties/type',
          type: 'string',
          title: 'The Type Schema',
          examples: ['VerifiablePresentation'],
          pattern: '^(.*)$'
        },
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

module.exports.instancesUpdate = () => instancesUpdate;
module.exports.instancesCreate = () => instancesCreate;
module.exports.instancesQuery = () => instancesQuery;
module.exports.presentation = () => presentation;

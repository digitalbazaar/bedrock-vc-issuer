/*!
* Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
*/
'use strict';

const bedrock = require('bedrock');
require('bedrock-security-context');
const {config: {constants}} = bedrock;

console.log('JJJJJJJJJ', constants);

/* eslint-disable quote-props, quotes, max-len */
exports.presentation = {
  "definitions": {},
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "http://example.com/root.json",
  "type": "object",
  "title": "The Root Schema",
  "required": [
    "controller",
    "presentation"
  ],
  "properties": {
    "controller": {
      "$id": "#/properties/controller",
      "type": "string",
      "title": "The Controller Schema",
      "default": "",
      "examples": [
        "urn:uuid:a99bfceb-f888-44f2-9319-d51e36038062"
      ],
      "pattern": "^(.*)$"
    },
    "presentation": {
      "$id": "#/properties/presentation",
      "type": "object",
      "title": "The Presentation Schema",
      "required": [
        "@context",
        "type",
        "holder",
        "capability",
        "proof"
      ],
      "properties": {
        "@context": {
          "$id": "#/properties/presentation/properties/@context",
          "type": "string",
          "title": "The @context Schema",
          "default": "",
          "examples": [
            "https://www.w3.org/2018/credentials/v1"
          ],
          "pattern": "^(.*)$"
        },
        "type": {
          "$id": "#/properties/presentation/properties/type",
          "type": "string",
          "title": "The Type Schema",
          "default": "",
          "examples": [
            "VerifiablePresentation"
          ],
          "pattern": "^(.*)$"
        },
        "holder": {
          "$id": "#/properties/presentation/properties/holder",
          "type": "string",
          "title": "The Holder Schema",
          "default": "",
          "examples": [
            "did:v1:test:nym:z6MkjrFvxZyHF6pNLqMynYSfL14oUkSPvENaqCUE2ygrtDNV"
          ],
          "pattern": "^(.*)$"
        },
        "capability": {
          "$id": "#/properties/presentation/properties/capability",
          "type": "array",
          "title": "The Capability Schema",
          "items": {
            "$id": "#/properties/presentation/properties/capability/items",
            "type": "object",
            "title": "The Items Schema",
            "required": [
              "@context",
              "id",
              "invoker",
              "delegator",
              "referenceId",
              "allowedAction",
              "invocationTarget",
              "parentCapability",
              "proof"
            ],
            "properties": {
              "@context": {
                "$id": "#/properties/presentation/properties/capability/items/properties/@context",
                "type": "string",
                "title": "The @context Schema",
                "default": "",
                "examples": [
                  "https://w3id.org/security/v2"
                ],
                "pattern": "^(.*)$"
              },
              "id": {
                "$id": "#/properties/presentation/properties/capability/items/properties/id",
                "type": "string",
                "title": "The Id Schema",
                "default": "",
                "examples": [
                  "urn:zcap:z1AERWyHhC9mHo81kgVb1xkNB"
                ],
                "pattern": "^(.*)$"
              },
              "invoker": {
                "$id": "#/properties/presentation/properties/capability/items/properties/invoker",
                "type": "string",
                "title": "The Invoker Schema",
                "default": "",
                "examples": [
                  "did:key:z6MkvE4Wsv95aWFbQjPRgK3yvTHkm4XwZcsDTBwfV6NEsbaL"
                ],
                "pattern": "^(.*)$"
              },
              "delegator": {
                "$id": "#/properties/presentation/properties/capability/items/properties/delegator",
                "type": "string",
                "title": "The Delegator Schema",
                "default": "",
                "examples": [
                  "did:key:z6MkvE4Wsv95aWFbQjPRgK3yvTHkm4XwZcsDTBwfV6NEsbaL"
                ],
                "pattern": "^(.*)$"
              },
              "referenceId": {
                "$id": "#/properties/presentation/properties/capability/items/properties/referenceId",
                "type": "string",
                "title": "The Referenceid Schema",
                "default": "",
                "examples": [
                  "7052b1bb-d013-4948-9829-d53a2db25d5c-edv-configuration"
                ],
                "pattern": "^(.*)$"
              },
              "allowedAction": {
                "$id": "#/properties/presentation/properties/capability/items/properties/allowedAction",
                "type": "array",
                "title": "The Allowedaction Schema",
                "items": {
                  "$id": "#/properties/presentation/properties/capability/items/properties/allowedAction/items",
                  "type": "string",
                  "title": "The Items Schema",
                  "default": "",
                  "examples": [
                    "read",
                    "write"
                  ],
                  "pattern": "^(.*)$"
                }
              },
              "invocationTarget": {
                "$id": "#/properties/presentation/properties/capability/items/properties/invocationTarget",
                "type": "object",
                "title": "The Invocationtarget Schema",
                "required": [
                  "id",
                  "type"
                ],
                "properties": {
                  "id": {
                    "$id": "#/properties/presentation/properties/capability/items/properties/invocationTarget/properties/id",
                    "type": "string",
                    "title": "The Id Schema",
                    "default": "",
                    "examples": [
                      "https://localhost:38443/edvs/z19m2uKN97sQN8FKcrFPrfMbB/documents"
                    ],
                    "pattern": "^(.*)$"
                  },
                  "type": {
                    "$id": "#/properties/presentation/properties/capability/items/properties/invocationTarget/properties/type",
                    "type": "string",
                    "title": "The Type Schema",
                    "default": "",
                    "examples": [
                      "urn:edv:documents"
                    ],
                    "pattern": "^(.*)$"
                  }
                }
              },
              "parentCapability": {
                "$id": "#/properties/presentation/properties/capability/items/properties/parentCapability",
                "type": "string",
                "title": "The Parentcapability Schema",
                "default": "",
                "examples": [
                  "https://localhost:38443/edvs/z19m2uKN97sQN8FKcrFPrfMbB/zcaps/documents"
                ],
                "pattern": "^(.*)$"
              },
              "proof": {
                "$id": "#/properties/presentation/properties/capability/items/properties/proof",
                "type": "object",
                "title": "The Proof Schema",
                "required": [
                  "type",
                  "created",
                  "verificationMethod",
                  "proofPurpose",
                  "capabilityChain",
                  "jws"
                ],
                "properties": {
                  "type": {
                    "$id": "#/properties/presentation/properties/capability/items/properties/proof/properties/type",
                    "type": "string",
                    "title": "The Type Schema",
                    "default": "",
                    "examples": [
                      "Ed25519Signature2018"
                    ],
                    "pattern": "^(.*)$"
                  },
                  "created": {
                    "$id": "#/properties/presentation/properties/capability/items/properties/proof/properties/created",
                    "type": "string",
                    "title": "The Created Schema",
                    "default": "",
                    "examples": [
                      "2020-01-15T18:27:46Z"
                    ],
                    "pattern": "^(.*)$"
                  },
                  "verificationMethod": {
                    "$id": "#/properties/presentation/properties/capability/items/properties/proof/properties/verificationMethod",
                    "type": "string",
                    "title": "The Verificationmethod Schema",
                    "default": "",
                    "examples": [
                      "did:key:z6Mko8RFFW776CFUvgKWXarcXuXqdyCHs7ZJdtnxxXmkd7Z5"
                    ],
                    "pattern": "^(.*)$"
                  },
                  "proofPurpose": {
                    "$id": "#/properties/presentation/properties/capability/items/properties/proof/properties/proofPurpose",
                    "type": "string",
                    "title": "The Proofpurpose Schema",
                    "default": "",
                    "examples": [
                      "capabilityDelegation"
                    ],
                    "pattern": "^(.*)$"
                  },
                  "capabilityChain": {
                    "$id": "#/properties/presentation/properties/capability/items/properties/proof/properties/capabilityChain",
                    "type": "array",
                    "title": "The Capabilitychain Schema",
                    "items": {
                      "$id": "#/properties/presentation/properties/capability/items/properties/proof/properties/capabilityChain/items",
                      "type": "string",
                      "title": "The Items Schema",
                      "default": "",
                      "examples": [
                        "https://localhost:38443/edvs/z19m2uKN97sQN8FKcrFPrfMbB/zcaps/documents"
                      ],
                      "pattern": "^(.*)$"
                    }
                  },
                  "jws": {
                    "$id": "#/properties/presentation/properties/capability/items/properties/proof/properties/jws",
                    "type": "string",
                    "title": "The Jws Schema",
                    "default": "",
                    "examples": [
                      "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..Yytxu-u7ycfOd0s9O9rxdhQqqTySpsOwQ7rmlaStv5RISOsQlAJtXkUfefqdmFt8oVgXi9_MK4P6JXsvGBGNAQ"
                    ],
                    "pattern": "^(.*)$"
                  }
                }
              }
            }
          }
        },
        "proof": {
          "$id": "#/properties/presentation/properties/proof",
          "type": "object",
          "title": "The Proof Schema",
          "required": [
            "type",
            "created",
            "proofPurpose",
            "verificationMethod",
            "challenge",
            "jws"
          ],
          "properties": {
            "type": {
              "$id": "#/properties/presentation/properties/proof/properties/type",
              "type": "string",
              "title": "The Type Schema",
              "default": "",
              "examples": [
                "Ed25519Signature2018"
              ],
              "pattern": "^(.*)$"
            },
            "created": {
              "$id": "#/properties/presentation/properties/proof/properties/created",
              "type": "string",
              "title": "The Created Schema",
              "default": "",
              "examples": [
                "2020-06-18T21:19:10Z"
              ],
              "pattern": "^(.*)$"
            },
            "proofPurpose": {
              "$id": "#/properties/presentation/properties/proof/properties/proofPurpose",
              "type": "string",
              "title": "The Proofpurpose Schema",
              "default": "",
              "examples": [
                "authentication"
              ],
              "pattern": "^(.*)$"
            },
            "verificationMethod": {
              "$id": "#/properties/presentation/properties/proof/properties/verificationMethod",
              "type": "string",
              "title": "The Verificationmethod Schema",
              "default": "",
              "examples": [
                "did:v1:test:nym:z6MkjrFvxZyHF6pNLqMynYSfL14oUkSPvENaqCUE2ygrtDNV#key"
              ],
              "pattern": "^(.*)$"
            },
            "challenge": {
              "$id": "#/properties/presentation/properties/proof/properties/challenge",
              "type": "string",
              "title": "The Challenge Schema",
              "default": "",
              "examples": [
                "c0ae1c8e-c7e7-469f-b252-86e6a0e7387e"
              ],
              "pattern": "^(.*)$"
            },
            "jws": {
              "$id": "#/properties/presentation/properties/proof/properties/jws",
              "type": "string",
              "title": "The Jws Schema",
              "default": "",
              "examples": [
                "BavEll0/I1..W3JT24="
              ],
              "pattern": "^(.*)$"
            }
          }
        }
      }
    }
  }
};

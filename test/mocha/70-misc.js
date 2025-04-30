/*!
 * Copyright (c) 2020-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import {mockData} from './mock.data.js';
import {randomUUID as uuid} from 'node:crypto';

const badCredentials = [
  {
    title: 'empty credential',
    credential: {},
    expect: {
      statusCode: 400,
      name: 'ValidationError',
      cause: {
        // FIXME non-BedrockError causes don't pass through
        // could add details.errors[] checks in this case
        //name: 'jsonld.ValidationError'
      }
    }
  },
  {
    title: 'unkonwn context',
    credential: {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'bogus.example'
      ],
      type: ['VerifiableCredential'],
      credentialSubject: {
        'ex:thing': true
      }
    },
    expect: {
      statusCode: 400,
      name: 'DataError',
      detailsError: {
        name: 'jsonld.InvalidUrl'
      }
    }
  },
  {
    title: 'empty subject',
    credential: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      credentialSubject: {}
    },
    expect: {
      // FIXME Improve @digitalbazaar/vc error handling.
      // This test is a plain 'Error' with a message of
      // '"credentialSubject" must make a claim.'.
      statusCode: 400
    }
  },
  {
    title: 'undefined terms',
    credential: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'UndefinedType'],
      credentialSubject: {
        undefinedTerm: 'notDefinedInContext'
      }
    },
    expect: {
      statusCode: 400,
      name: 'DataError',
      message: 'Invalid credential.',
      detailsError: {
        name: 'jsonld.ValidationError'
      }
    }
  }
];

describe('fail for bad credentials', () => {
  let suites;
  let capabilityAgent;
  let zcaps;
  let noStatusListIssuerId;
  let noStatusListIssuerRootZcap;
  beforeEach(async () => {
    // generate a proof set using all of these suites in each test
    suites = [{
      name: 'Ed25519Signature2020',
      algorithm: 'Ed25519'
    }, {
      name: 'eddsa-rdfc-2022',
      algorithm: 'Ed25519'
    }, {
      name: 'eddsa-jcs-2022',
      algorithm: 'Ed25519'
    }, {
      name: 'ecdsa-rdfc-2019',
      algorithm: 'P-256'
    }, {
      name: 'ecdsa-jcs-2019',
      algorithm: 'P-256'
    }, {
      name: 'ecdsa-sd-2023',
      algorithm: 'P-256',
      // require these options (do not allow client to override)
      options: {
        mandatoryPointers: ['/issuer']
      }
    }, {
      name: 'ecdsa-xi-2023',
      algorithm: 'P-256'
    }, {
      name: 'bbs-2023',
      algorithm: 'Bls12381G2',
      // require these options (do not allow client to override)
      options: {
        mandatoryPointers: ['/issuer']
      }
    }];

    // generate a `did:web` DID for the issuer
    const {host} = bedrock.config.server;
    const localId = uuid();
    const did = `did:web:${encodeURIComponent(host)}:did-web:${localId}`;

    // provision dependencies
    ({capabilityAgent, zcaps} = await helpers.provisionDependencies({
      did, cryptosuites: suites, status: false, zcaps: true
    }));

    // create issue options
    const issueOptions = {
      issuer: did,
      cryptosuites: suites.map(suite => {
        const {name, options, zcapReferenceIds} = suite;
        const cryptosuite = {name, zcapReferenceIds};
        if(options) {
          cryptosuite.options = options;
        }
        return cryptosuite;
      })
    };

    // create `did:web` DID document for issuer
    const didDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
        'https://w3id.org/security/multikey/v1'
      ],
      id: did,
      verificationMethod: [],
      assertionMethod: []
    };
    for(const {assertionMethodKey} of suites) {
      const description = await assertionMethodKey.getKeyDescription();
      delete description['@context'];
      didDocument.verificationMethod.push(description);
      didDocument.assertionMethod.push(description.id);
    }
    // add DID doc to map with DID docs to be served
    mockData.didWebDocuments.set(localId, didDocument);

    // create issuer instance w/ no status list options
    const noStatusListIssuerConfig = await helpers.createIssuerConfig({
      capabilityAgent, zcaps, issueOptions
    });
    noStatusListIssuerId = noStatusListIssuerConfig.id;
    noStatusListIssuerRootZcap =
      `urn:zcap:root:${encodeURIComponent(noStatusListIssuerId)}`;
  });
  for(const testCred of badCredentials) {
    // handle 'skip' and 'only' flags.
    let _it;
    if(testCred.skip) {
      _it = it.skip;
    } else if(testCred.only) {
      _it = it.only;
    } else {
      _it = it;
    }
    _it(`fails for ${testCred.title}`, async () => {
      const credential = structuredClone(
        registryEntryFile(testCred.credential));
      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${noStatusListIssuerId}/credentials/issue`,
          capability: noStatusListIssuerRootZcap,
          json: {
            credential,
            options: {
              extraInformation: 'abc'
            }
          }
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      should.not.exist(result);
      if(testCred.expect.statusCode) {
        error.status.should.equal(testCred.expect.statusCode);
      }
      if(testCred.expect.name) {
        error.data.name.should.equal(testCred.expect.name);
      }
      if(testCred.expect.message) {
        error.data.message.should.equal(testCred.expect.message);
      }
      if(testCred.expect?.cause?.name) {
        error.data.cause.name.should.equal(testCred.expect.cause.name);
      }
      if(testCred.expect?.detailsError?.name) {
        error.data.details.error.name.should.equal(
          testCred.expect.detailsError.name);
      }
    });
  }
});

/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
//import {createRequire} from 'node:module';
import {klona} from 'klona';
import {mockData} from './mock.data.js';
import {v4 as uuid} from 'uuid';

//const require = createRequire(import.meta.url);

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
//const mockCredential = require('./mock-credential.json');
//const mockCredentialV2 = require('./mock-credential-v2.json');

const badCredentials = [
  {
    title: 'empty credential',
    credential: {},
    expect: {
      statusCode: 400,
      name: 'ValidationError',
      message: null
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
      // FIXME
      statusCode: 400,
      name: 'jsonld.InvalidUrl',
      message: null
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
      // FIXME
      statusCode: 500,
      name: null,
      message: null
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
      name: 'SyntaxError',
      message: 'Invalid credential.'
    }
  }
];

describe.only('fail for bed credentials', () => {
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
      name: 'ecdsa-rdfc-2019',
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
  // filter using 'only' and 'skip'
  const _hasOnly = badCredentials.some(c => c.skip !== true && c.only === true);
  const _badCredentials = badCredentials
    .filter(c => c.skip !== true)
    .filter(c => !_hasOnly || c.only === true);
  for(const testCred of _badCredentials) {
    it(`fails for ${testCred.title}`, async () => {
      const credential = klona(testCred.credential);
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
      if(testCred.expect.name !== null) {
        error.data.name.should.equal(testCred.expect.name);
      }
      if(testCred.expect.message !== null) {
        error.data.message.should.equal(testCred.expect.message);
      }
    });
  }
});

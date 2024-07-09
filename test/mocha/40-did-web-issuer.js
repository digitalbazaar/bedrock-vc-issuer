/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import {createRequire} from 'node:module';
import {klona} from 'klona';
import {mockData} from './mock.data.js';
import {v4 as uuid} from 'uuid';

const require = createRequire(import.meta.url);

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');
const mockCredentialV2 = require('./mock-credential-v2.json');

describe('issue using "did:web" issuer', () => {
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
  describe('/credentials/issue', () => {
    it('issues a VC 1.1 credential with a proof set', async () => {
      const credential = klona(mockCredential);
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
      assertNoError(error);
      should.exist(result.data);
      should.exist(result.data.verifiableCredential);
      const {verifiableCredential} = result.data;
      verifiableCredential.should.be.an('object');
      should.exist(verifiableCredential['@context']);
      should.exist(verifiableCredential.id);
      should.exist(verifiableCredential.type);
      should.exist(verifiableCredential.issuer);
      should.exist(verifiableCredential.issuanceDate);
      should.exist(verifiableCredential.credentialSubject);
      verifiableCredential.credentialSubject.should.be.an('object');
      should.not.exist(verifiableCredential.credentialStatus);
      should.exist(verifiableCredential.proof);
      verifiableCredential.proof.should.be.an('array');
      verifiableCredential.proof.length.should.equal(suites.length);
      const parsedCryptosuites = verifiableCredential.proof.map(
        ({type, cryptosuite}) => cryptosuite ?? type);
      const expectedCryptosuites = suites.map(({name}) => name);
      parsedCryptosuites.should.deep.equal(expectedCryptosuites);
    });
    it('issues a VC 2.0 credential with a proof set', async () => {
      const credential = klona(mockCredentialV2);
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
      assertNoError(error);
      should.exist(result.data);
      should.exist(result.data.verifiableCredential);
      const {verifiableCredential} = result.data;
      verifiableCredential.should.be.an('object');
      should.exist(verifiableCredential['@context']);
      should.exist(verifiableCredential.id);
      should.exist(verifiableCredential.type);
      should.exist(verifiableCredential.issuer);
      should.exist(verifiableCredential.credentialSubject);
      verifiableCredential.credentialSubject.should.be.an('object');
      should.not.exist(verifiableCredential.credentialStatus);
      should.exist(verifiableCredential.proof);
      verifiableCredential.proof.should.be.an('array');
      verifiableCredential.proof.length.should.equal(suites.length);
      const parsedCryptosuites = verifiableCredential.proof.map(
        ({type, cryptosuite}) => cryptosuite ?? type);
      const expectedCryptosuites = suites.map(({name}) => name);
      parsedCryptosuites.should.deep.equal(expectedCryptosuites);
    });
  });
});

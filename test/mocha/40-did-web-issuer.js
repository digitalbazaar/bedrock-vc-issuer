/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {createRequire} from 'node:module';
import {httpClient} from '@digitalbazaar/http-client';
import {klona} from 'klona';
import {mockData} from './mock.data.js';
import {v4 as uuid} from 'uuid';

const require = createRequire(import.meta.url);

const {baseUrl} = mockData;
const serviceType = 'vc-issuer';

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');
const mockCredentialV2 = require('./mock-credential-v2.json');

describe('issue using "did:web" issuer', () => {
  let suites;
  let capabilityAgent;
  let keystoreAgent;
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
      algorithm: 'P-256'
    }, {
      name: 'ecdsa-xi-2023',
      algorithm: 'P-256'
    }, {
      name: 'bbs-2023',
      algorithm: 'Bls12381G2'
    }];

    // generate a `did:web` DID for the issuer
    const {host} = bedrock.config.server;
    const localId = uuid();
    const did = `did:web:${encodeURIComponent(host)}:did-web:${localId}`;

    // provision dependencies
    ({capabilityAgent, keystoreAgent} = await helpers.provisionDependencies({
      did, cryptosuites: suites, status: false
    }));

    // create EDV for storage (creating hmac and kak in the process)
    const {
      edvConfig,
      hmac,
      keyAgreementKey
    } = await helpers.createEdv({capabilityAgent, keystoreAgent});

    // get service agent to delegate to
    const serviceAgentUrl =
      `${baseUrl}/service-agents/${encodeURIComponent(serviceType)}`;
    const {data: serviceAgent} = await httpClient.get(serviceAgentUrl, {agent});

    // delegate edv, hmac, and key agreement key zcaps to service agent
    const zcaps = await helpers.delegateEdvZcaps({
      edvConfig, hmac, keyAgreementKey, serviceAgent,
      capabilityAgent
    });

    // delegate assertion method keys
    await helpers.delegateAssertionMethodZcaps({
      cryptosuites: suites, serviceAgent, capabilityAgent, zcaps
    });

    // create issue options
    const issueOptions = {
      issuer: did,
      cryptosuites: suites.map(
        ({name, zcapReferenceIds}) => ({name, zcapReferenceIds}))
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
              extraInformation: 'abc',
              mandatoryPointers: ['/issuer']
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

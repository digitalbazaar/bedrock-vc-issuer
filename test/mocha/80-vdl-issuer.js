/*!
 * Copyright (c) 2020-2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import * as vdlAamvaContext from '@digitalbazaar/vdl-aamva-context';
import * as vdlContext from '@digitalbazaar/vdl-context';
import {createRequire} from 'node:module';
import {mockData} from './mock.data.js';
import {randomUUID as uuid} from 'node:crypto';

const require = createRequire(import.meta.url);

const mockVDL = require('./mock-vdl.json');
const mockDeprecatedVDL = require('./mock-vdl-deprecated.json');

describe('issue vDL', () => {
  let capabilityAgent;
  let did;
  let zcaps;
  let noStatusListIssuerId;
  let noStatusListIssuerRootZcap;
  beforeEach(async () => {
    const suiteName = 'ecdsa-sd-2023';
    const algorithm = 'P-256';
    const depOptions = {
      status: false,
      suiteOptions: {
        suiteName,
        issueOptions: {},
        statusOptions: {
          // sign any status list with simple ECDSA
          // note: status not presently used in this test
          suiteName: 'ecdsa-rdfc-2019',
          algorithm
        },
        terseIssueOptions: {mandatoryPointers: ['/issuer']}
      },
      cryptosuites: [{
        name: suiteName,
        algorithm
      }]
    };

    // generate a `did:web` DID for the issuer
    const {host} = bedrock.config.server;
    const localId = uuid();
    did = `did:web:${encodeURIComponent(host)}:did-web:${localId}`;

    // provision dependencies
    let issuer;
    ({issuer, capabilityAgent, zcaps} = await helpers.provisionDependencies({
      ...depOptions,
      did,
      status: false,
      zcaps: true
    }));

    // create issue options
    const {cryptosuites} = depOptions;
    const issueOptions = helpers.createIssueOptions({issuer, cryptosuites});
    // add `ecdsa-rdfc-2019` as an additional cryptosuite to sign with using
    // the same assertion method key / zcap
    issueOptions.cryptosuites = [{
      ...issueOptions.cryptosuites[0],
      name: 'ecdsa-rdfc-2019'
    }, issueOptions.cryptosuites[0]];

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
    for(const {assertionMethodKey} of cryptosuites) {
      const description = await assertionMethodKey.getKeyDescription();
      delete description['@context'];
      didDocument.verificationMethod.push(description);
      didDocument.assertionMethod.push(description.id);
    }
    // add DID doc to map with DID docs to be served
    mockData.didWebDocuments.set(localId, didDocument);

    // add vDL contexts to issuer instance
    const contexts = [
      {id: vdlContext.CONTEXT_URL, context: vdlContext.CONTEXT},
      {id: vdlAamvaContext.CONTEXT_URL, context: vdlAamvaContext.CONTEXT}
    ];

    // create issuer instance w/ no status list options
    const noStatusListIssuerConfig = await helpers.createIssuerConfig({
      capabilityAgent, zcaps, issueOptions, contexts
    });
    noStatusListIssuerId = noStatusListIssuerConfig.id;
    noStatusListIssuerRootZcap =
      `urn:zcap:root:${encodeURIComponent(noStatusListIssuerId)}`;
  });
  it('issues a modern vDL w/traditional and SD ECDSA proofs', async () => {
    const credential = structuredClone(mockVDL);
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${noStatusListIssuerId}/credentials/issue`,
        capability: noStatusListIssuerRootZcap,
        json: {credential}
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
    should.exist(verifiableCredential.type);
    should.exist(verifiableCredential.proof);
    verifiableCredential.proof.should.be.an('array');
    verifiableCredential.proof[0].cryptosuite.should.equal('ecdsa-rdfc-2019');
    verifiableCredential.proof[1].cryptosuite.should.equal('ecdsa-sd-2023');

    // assert contents
    const expectedCredential = {
      ...mockVDL,
      issuer: {
        ...mockVDL.issuer,
        id: did
      },
      // copy proof from VC
      proof: verifiableCredential.proof
    };
    verifiableCredential.should.deep.equal(expectedCredential);
  });
  it('issues a deprecated v1 vDL', async () => {
    const credential = structuredClone(mockDeprecatedVDL);
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${noStatusListIssuerId}/credentials/issue`,
        capability: noStatusListIssuerRootZcap,
        json: {credential}
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
    should.exist(verifiableCredential.type);
    should.exist(verifiableCredential.proof);
    verifiableCredential.proof.should.be.an('array');
    verifiableCredential.proof[0].cryptosuite.should.equal('ecdsa-rdfc-2019');
    verifiableCredential.proof[1].cryptosuite.should.equal('ecdsa-sd-2023');

    // assert contents
    const expectedCredential = {
      ...mockDeprecatedVDL,
      ['@context']: [
        ...mockDeprecatedVDL['@context'],
        'https://w3id.org/security/data-integrity/v2'
      ],
      issuer: {
        ...mockDeprecatedVDL.issuer,
        id: did
      },
      // copy proof from VC
      proof: verifiableCredential.proof
    };
    verifiableCredential.should.deep.equal(expectedCredential);
  });
});

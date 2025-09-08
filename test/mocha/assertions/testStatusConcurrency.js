/*!
 * Copyright (c) 2020-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as assertions from './index.js';
import * as helpers from '../helpers.js';
import PQueue from 'p-queue';
import {randomUUID as uuid} from 'node:crypto';

/* eslint-disable */
const CREDENTIAL_TEMPLATE = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2"
  ],
  "type": ["VerifiableCredential"],
  "issuer": "did:example:1234",
  "credentialSubject": {
    "name": "A name"
  }
}
/* eslint-enable */

export function testStatusConcurrency({
  suiteName, algorithm, issueOptions, statusOptions
}) {
  describe('BitstringStatusList concurrency', function() {
    const depOptions = {
      suiteOptions: {
        suiteName, algorithm, issueOptions, statusOptions
      },
      cryptosuites: [{
        name: suiteName,
        algorithm
      }],
      zcaps: true
    };
    let issuer;
    let capabilityAgent;
    let zcaps;
    let bslInstance;
    before(async () => {
      // provision dependencies
      ({issuer, capabilityAgent, zcaps} = await helpers.provisionDependencies(
        depOptions));

      // create issuer instance w/ bitstring status list options
      const statusListOptions = [{
        type: 'BitstringStatusList',
        statusPurpose: 'revocation',
        zcapReferenceIds: {
          createCredentialStatusList: 'createCredentialStatusList'
        }
      }];
      const {cryptosuites} = depOptions;
      const issueOptions = helpers.createIssueOptions({issuer, cryptosuites});
      bslInstance = await helpers.createIssuerConfigAndDependencies({
        capabilityAgent, zcaps, issueOptions, statusListOptions, depOptions
      });
    });
    it('issues many VCs w/status concurrently', async function() {
      // two minutes to issue concurrently
      this.timeout(1000 * 60 * 2);

      const zcapClient = helpers.createZcapClient({capabilityAgent});

      // generate 100 VCs with a concurrency of 10
      const queue = new PQueue({concurrency: 10});
      for(let i = 0; i < 100; ++i) {
        queue.add(async () => {
          const credential = structuredClone(CREDENTIAL_TEMPLATE);
          const credentialId = `urn:uuid:${uuid()}`;
          let error;
          let result;
          try {
            result = await zcapClient.write({
              url: `${bslInstance.issuerId}/credentials/issue`,
              capability: bslInstance.rootZcap,
              json: {
                credential,
                options: {...issueOptions, credentialId}
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
          should.not.exist(verifiableCredential.id);
          should.exist(verifiableCredential.type);
          should.exist(verifiableCredential.issuer);
          should.exist(verifiableCredential.credentialSubject);
          verifiableCredential.credentialSubject.should.be.an('object');
          should.exist(verifiableCredential.credentialStatus);
          should.exist(verifiableCredential.proof);
          verifiableCredential.proof.should.be.an('object');
          await assertions.assertStoredCredential({
            configId: bslInstance.issuerId,
            credentialId,
            zcapClient,
            capability: bslInstance.rootZcap,
            expectedCredential: verifiableCredential
          });
        });
      }
      await queue.onIdle();
    });
  });
}

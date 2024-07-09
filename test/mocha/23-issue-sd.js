/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as assertions from './assertions.js';
import * as helpers from './helpers.js';
import {createRequire} from 'node:module';
import {klona} from 'klona';

const require = createRequire(import.meta.url);

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');

describe('issue w/selective disclosure options', () => {
  const suiteNames = {
    'ecdsa-sd-2023': {
      algorithm: ['P-256']
    },
    'bbs-2023': {
      algorithm: ['Bls12381G2']
    }
  };
  for(const suiteName in suiteNames) {
    const suiteInfo = suiteNames[suiteName];
    const {issueOptions} = suiteInfo;
    const algorithms = Array.isArray(suiteInfo.algorithm) ?
      suiteInfo.algorithm : [suiteInfo.algorithm];
    for(const algorithm of algorithms) {
      describeSuite({
        suiteName, algorithm, issueOptions
      });
    }
  }
  function describeSuite({suiteName, algorithm, issueOptions}) {
    const testDescription = `${suiteName}, algorithm: ${algorithm}`;
    const depOptions = {
      status: false,
      suiteOptions: {
        suiteName, algorithm, issueOptions
      },
      cryptosuites: [{
        name: suiteName,
        algorithm
      }],
      zcaps: true
    };
    describe(testDescription, function() {
      let capabilityAgent;
      let zcaps;
      let noStatusListIssuerId;
      let noStatusListIssuerRootZcap;
      before(async () => {
        // provision dependencies
        ({capabilityAgent, zcaps} = await helpers.provisionDependencies(
          depOptions));

        // create issuer instance w/ no status list options
        const noStatusListIssuerConfig = await helpers.createIssuerConfig(
          {capabilityAgent, zcaps, suiteName});
        noStatusListIssuerId = noStatusListIssuerConfig.id;
        noStatusListIssuerRootZcap = helpers.createRootZcap({
          url: noStatusListIssuerId
        });
      });
      describe('/credentials/issue', () => {
        it('issues a valid credential w/ "options.mandatoryPointers"',
          async () => {
            const credential = klona(mockCredential);
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            const {verifiableCredential} = await assertions.issueAndAssert({
              configId: noStatusListIssuerId,
              credential,
              issueOptions: {
                ...issueOptions,
                mandatoryPointers: ['/issuer']
              },
              zcapClient,
              capability: noStatusListIssuerRootZcap
            });
            should.exist(verifiableCredential.id);
            should.not.exist(verifiableCredential.credentialStatus);
          });
        it('fails to issue a valid credential w/ invalid ' +
          '"options.mandatoryPointers"', async () => {
          let error;
          const missingPointer = '/nonExistentPointer';
          try {
            const credential = klona(mockCredential);
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            await zcapClient.write({
              url: `${noStatusListIssuerId}/credentials/issue`,
              capability: noStatusListIssuerRootZcap,
              json: {
                credential,
                options: {
                  ...issueOptions,
                  mandatoryPointers: [missingPointer]
                }
              }
            });
          } catch(e) {
            error = e;
          }
          should.exist(error);
          error.data.type.should.equal('DataError');
          error.status.should.equal(400);
          error.data.message.should.equal(
            `JSON pointer "${missingPointer}" does not match document.`);
        });
      });
    });
  }
});

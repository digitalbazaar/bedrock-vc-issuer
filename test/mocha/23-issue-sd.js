/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as assertions from './assertions.js';
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {createRequire} from 'node:module';
import {httpClient} from '@digitalbazaar/http-client';
import {klona} from 'klona';
import {mockData} from './mock.data.js';

const require = createRequire(import.meta.url);

const {baseUrl} = mockData;
const serviceType = 'vc-issuer';

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
    if(Array.isArray(suiteInfo.algorithm)) {
      for(const algorithm of suiteInfo.algorithm) {
        describeSuite({suiteName, algorithm, issueOptions});
      }
    } else {
      describeSuite({suiteName, algorithm: suiteInfo.algorithm, issueOptions});
    }
  }
  function describeSuite({suiteName, algorithm, issueOptions}) {
    const testDescription = `${suiteName}, algorithm: ${algorithm}`;
    const depOptions = {
      status: false,
      suiteOptions: {
        suiteName, algorithm, issueOptions
      }
    };
    describe(testDescription, function() {
      let capabilityAgent;
      let keystoreAgent;
      let noStatusListIssuerId;
      let noStatusListIssuerRootZcap;
      before(async () => {
        // provision dependencies
        ({capabilityAgent, keystoreAgent} = await helpers.provisionDependencies(
          depOptions));

        // generate key for signing VCs (make it a did:key DID for simplicity)
        const publicAliasTemplate =
          'did:key:{publicKeyMultibase}#{publicKeyMultibase}';
        const assertionMethodKey = await helpers._generateMultikey({
          keystoreAgent,
          type: `urn:webkms:multikey:${algorithm}`,
          publicAliasTemplate
        });

        // create EDV for storage (creating hmac and kak in the process)
        const {
          edvConfig,
          hmac,
          keyAgreementKey
        } = await helpers.createEdv({capabilityAgent, keystoreAgent});

        // get service agent to delegate to
        const serviceAgentUrl =
          `${baseUrl}/service-agents/${encodeURIComponent(serviceType)}`;
        const {data: serviceAgent} = await httpClient.get(
          serviceAgentUrl, {agent});

        // delegate edv, hmac, and key agreement key zcaps to service agent
        const zcaps = await helpers.delegateEdvZcaps({
          edvConfig, hmac, keyAgreementKey, serviceAgent,
          capabilityAgent
        });
        // delegate assertion method zcap to service agent
        zcaps.assertionMethod = await helpers.delegate({
          capability: helpers.createRootZcap({
            url: helpers.parseKeystoreId(assertionMethodKey.kmsId)
          }),
          controller: serviceAgent.id,
          invocationTarget: assertionMethodKey.kmsId,
          delegator: capabilityAgent
        });

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

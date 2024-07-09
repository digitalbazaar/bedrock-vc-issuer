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
const mockCredentialV2 = require('./mock-credential-v2.json');

describe('issue w/o status APIs', () => {
  const suiteNames = {
    Ed25519Signature2020: {
      algorithm: 'Ed25519'
    },
    'eddsa-rdfc-2022': {
      algorithm: 'Ed25519'
    },
    'ecdsa-rdfc-2019': {
      algorithm: ['P-256', 'P-384']
    },
    'ecdsa-sd-2023': {
      algorithm: ['P-256']
    },
    'ecdsa-xi-2023': {
      algorithm: ['P-256', 'P-384'],
      issueOptions: {
        extraInformation: 'abc'
      }
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
        let assertionMethodKey;
        const publicAliasTemplate =
          'did:key:{publicKeyMultibase}#{publicKeyMultibase}';
        if(['P-256', 'P-384', 'Bls12381G2'].includes(algorithm)) {
          assertionMethodKey = await helpers._generateMultikey({
            keystoreAgent,
            type: `urn:webkms:multikey:${algorithm}`,
            publicAliasTemplate
          });
        } else {
          assertionMethodKey = await keystoreAgent.generateKey({
            type: 'asymmetric',
            publicAliasTemplate
          });
        }

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
        it('issues a valid credential w/no "credentialStatus"', async () => {
          const credential = klona(mockCredential);
          const zcapClient = helpers.createZcapClient({capabilityAgent});
          const {verifiableCredential} = await assertions.issueAndAssert({
            configId: noStatusListIssuerId,
            credential,
            issueOptions,
            zcapClient,
            capability: noStatusListIssuerRootZcap
          });
          should.exist(verifiableCredential.id);
          should.not.exist(verifiableCredential.credentialStatus);
        });
        it('issues a VC 2.0 credential w/no "credentialStatus"', async () => {
          const credential = klona(mockCredentialV2);
          const zcapClient = helpers.createZcapClient({capabilityAgent});
          const {verifiableCredential} = await assertions.issueAndAssert({
            configId: noStatusListIssuerId,
            credential,
            issueOptions,
            zcapClient,
            capability: noStatusListIssuerRootZcap
          });
          should.exist(verifiableCredential.id);
          should.not.exist(verifiableCredential.credentialStatus);
        });

        it('fails to issue an empty credential', async () => {
          let error;
          try {
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            await zcapClient.write({
              url: `${noStatusListIssuerId}/credentials/issue`,
              capability: noStatusListIssuerRootZcap,
              json: {
                credential: {}
              }
            });
          } catch(e) {
            error = e;
          }
          should.exist(error);
          error.data.type.should.equal('ValidationError');
        });
      });
    });
  }
});

/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {createRequire} from 'node:module';
import {httpClient} from '@digitalbazaar/http-client';
import {issuer} from '@bedrock/vc-issuer';
import {klona} from 'klona';
import {mockData} from './mock.data.js';
import sinon from 'sinon';
import {v4 as uuid} from 'uuid';

const require = createRequire(import.meta.url);

const {_CredentialStatusWriter} = issuer;

const {baseUrl} = mockData;
const serviceType = 'vc-issuer';

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');
const mockTerseCredential = require('./mock-terse-credential.json');

describe('issue crash recovery', () => {
  const suiteNames = {
    'eddsa-rdfc-2022': {
      algorithm: 'Ed25519',
      statusOptions: {
        suiteName: 'eddsa-rdfc-2022'
      }
    }
  };
  for(const suiteName in suiteNames) {
    const suiteInfo = suiteNames[suiteName];
    const {issueOptions, statusOptions, terseIssueOptions} = suiteInfo;
    if(Array.isArray(suiteInfo.algorithm)) {
      for(const algorithm of suiteInfo.algorithm) {
        describeSuite({
          suiteName, algorithm, issueOptions, statusOptions, terseIssueOptions
        });
      }
    } else {
      describeSuite({
        suiteName, algorithm: suiteInfo.algorithm, issueOptions,
        statusOptions, terseIssueOptions
      });
    }
  }
  function describeSuite({
    suiteName, algorithm, issueOptions, statusOptions,
    terseIssueOptions = issueOptions
  }) {
    const testDescription = `${suiteName}, algorithm: ${algorithm}`;
    const depOptions = {
      suiteOptions: {
        suiteName, algorithm, issueOptions, statusOptions, terseIssueOptions
      }
    };
    describe(testDescription, function() {
      let capabilityAgent;
      let keystoreAgent;
      let bslRevocation;
      let smallBsl;
      let smallTerseStatusList;
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

        // create issuer instance w/ bitstring status list options
        // w/ revocation status purpose
        {
          const statusListOptions = [{
            type: 'BitstringStatusList',
            statusPurpose: 'revocation',
            zcapReferenceIds: {
              createCredentialStatusList: 'createCredentialStatusList'
            }
          }];
          bslRevocation = await helpers.createIssuerConfigAndDependencies({
            capabilityAgent, zcaps, suiteName, statusListOptions, depOptions
          });
        }

        // create issuer instance w/ small status list
        {
          const statusListOptions = [{
            type: 'BitstringStatusList',
            statusPurpose: 'revocation',
            options: {
              blockSize: 8,
              blockCount: 1
            },
            zcapReferenceIds: {
              createCredentialStatusList: 'createCredentialStatusList'
            }
          }];
          smallBsl = await helpers.createIssuerConfigAndDependencies({
            capabilityAgent, zcaps, suiteName, statusListOptions, depOptions
          });
        }

        // create issuer instance w/ small terse status list
        {
          const statusListOptions = [{
            type: 'TerseBitstringStatusList',
            statusPurpose: 'revocation',
            options: {
              blockSize: 8,
              blockCount: 1,
              listCount: 2
            },
            zcapReferenceIds: {
              createCredentialStatusList: 'createCredentialStatusList'
            }
          }];
          smallTerseStatusList = await helpers
            .createIssuerConfigAndDependencies({
              capabilityAgent, zcaps, suiteName, statusListOptions, depOptions
            });

          // insert example context for issuing VCs w/terse status entries
          const {
            testBarcodeCredentialContextUrl,
            testBarcodeCredentialContext
          } = mockData;
          const client = helpers.createZcapClient({capabilityAgent});
          const url = `${smallTerseStatusList.issuerId}/contexts`;
          await client.write({
            url, json: {
              id: testBarcodeCredentialContextUrl,
              context: testBarcodeCredentialContext
            },
            capability: smallTerseStatusList.rootZcap
          });
        }
      });

      describe('/credential/issue crash recovery', () => {
        // stub modules in order to simulate failure conditions
        let credentialStatusWriterStub;
        let mathRandomStub;
        before(async () => {
          // make Math.random always return 0
          // this will ensure that the same shard is selected every time
          // see _chooseRandom helper in ListManager.js
          mathRandomStub = sinon.stub(Math, 'random').callsFake(() => 0);
          // make credentialStatusWriter.finish a noop
          // making this a noop is simulating a failure where the status list
          // bookkeeping was not completed after an issuance
          credentialStatusWriterStub = sinon.stub(
            _CredentialStatusWriter.prototype, 'finish').callsFake(
            async () => {});
        });
        after(async () => {
          mathRandomStub.restore();
          credentialStatusWriterStub.restore();
        });

        // FIXME: add a test that finishes one credential writer but not
        // another, resulting in a duplicate being detected for one status
        // but not another -- and a successful recovery from this condition

        it('successfully recovers from a simulated crash', async () => {
          const zcapClient = helpers.createZcapClient({capabilityAgent});

          // first issue a VC that is partially completed enough to return the
          // VC, however, the status list index bookkeeping is not updated
          // The earlier failure is detected by the second issue of a VC and
          // the bookkeeping is repaired
          const credential1 = klona(mockCredential);
          credential1.id = 'urn:id1';
          const {data: {verifiableCredential: vc1}} = await zcapClient.write({
            url: `${bslRevocation.issuerId}/credentials/issue`,
            capability: bslRevocation.rootZcap,
            json: {credential: credential1, options: issueOptions}
          });

          const vc1StatusId = vc1.credentialStatus.id;

          // now issue second VC (should succeed and process the
          const credential2 = klona(mockCredential);
          credential2.id = 'urn:id2';
          const {data: {verifiableCredential: vc2}} = await zcapClient.write({
            url: `${bslRevocation.issuerId}/credentials/issue`,
            capability: bslRevocation.rootZcap,
            json: {credential: credential2, options: issueOptions}
          });

          const vc2StatusId = vc2.credentialStatus.id;

          // this test ensures that the two credentials are not issued with the
          // same status list index / hash fragment
          vc1StatusId.should.not.equal(vc2StatusId);
          const vc1StatusHash = parseInt(vc1StatusId.split('#')[1]);
          const vc2StatusHash = parseInt(vc2StatusId.split('#')[1]);
          vc1StatusHash.should.not.equal(vc2StatusHash);
        });
        // ensure duplicate VCs are still properly detected when bookkeeping
        // fails
        it('fails when trying to issue a duplicate credential', async () => {
          const zcapClient = helpers.createZcapClient({capabilityAgent});

          // issue VC (should succeed)
          let credential = klona(mockCredential);
          let error;
          let result;
          try {
            result = await zcapClient.write({
              url: `${bslRevocation.issuerId}/credentials/issue`,
              capability: bslRevocation.rootZcap,
              json: {credential, options: issueOptions}
            });
          } catch(e) {
            error = e;
          }
          assertNoError(error);
          should.exist(result.data);
          should.exist(result.data.verifiableCredential);
          const {verifiableCredential} = result.data;
          const {proof} = verifiableCredential;
          should.exist(proof);

          // issue VC with the same ID again (should fail)
          credential = klona(mockCredential);
          result = undefined;
          try {
            result = await zcapClient.write({
              url: `${bslRevocation.issuerId}/credentials/issue`,
              capability: bslRevocation.rootZcap,
              json: {credential, options: issueOptions}
            });
          } catch(e) {
            error = e;
          }
          should.exist(error);
          error.data.type.should.equal('DuplicateError');
        });

        it('fails to issue with a duplicate "credentialId"', async () => {
          const zcapClient = helpers.createZcapClient({capabilityAgent});

          // issue VC without `id` and no `credentialId` option
          // (should succeed)
          {
            const credential = klona(mockCredential);
            delete credential.id;
            let error;
            let result;
            try {
              result = await zcapClient.write({
                url: `${bslRevocation.issuerId}/credentials/issue`,
                capability: bslRevocation.rootZcap,
                json: {
                  credential,
                  options: {issueOptions}
                }
              });
            } catch(e) {
              error = e;
            }
            assertNoError(error);
            should.exist(result.data);
            should.exist(result.data.verifiableCredential);
            const {verifiableCredential} = result.data;
            const {proof} = verifiableCredential;
            should.exist(proof);
          }

          // issue VC with "credentialId" option only (should succeed)
          const credentialId = `urn:uuid:${uuid()}`;
          {
            const credential = klona(mockCredential);
            delete credential.id;
            let error;
            let result;
            try {
              result = await zcapClient.write({
                url: `${bslRevocation.issuerId}/credentials/issue`,
                capability: bslRevocation.rootZcap,
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
            const {proof} = verifiableCredential;
            should.exist(proof);
          }

          // issue VC with the same "credentialId" again (should fail)
          {
            const credential = klona(mockCredential);
            delete credential.id;
            let error;
            let result;
            try {
              result = await zcapClient.write({
                url: `${bslRevocation.issuerId}/credentials/issue`,
                capability: bslRevocation.rootZcap,
                json: {
                  credential,
                  options: {...issueOptions, credentialId}
                }
              });
            } catch(e) {
              error = e;
            }
            should.exist(error);
            error.data.type.should.equal('DuplicateError');
            should.not.exist(result);
          }
        });

        it('issues VCs with list rollover', async function() {
          // two minutes to issue and rollover lists
          this.timeout(1000 * 60 * 2);

          // list length is 8, do two rollovers
          const listLength = 8;
          for(let i = 0; i < (listLength * 2 + 1); ++i) {
            // first issue VC
            const credential = klona(mockCredential);
            credential.id = `urn:uuid:${uuid()}`;
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            const {data: {verifiableCredential}} = await zcapClient.write({
              url: `${smallBsl.issuerId}/credentials/issue`,
              capability: smallBsl.rootZcap,
              json: {credential, options: issueOptions}
            });

            // get VC status
            const statusInfo = await helpers.getCredentialStatus(
              {verifiableCredential});
            let {status} = statusInfo;
            status.should.equal(false);

            // then revoke VC
            let error;
            try {
              const {statusListOptions: [{indexAllocator}]} =
                smallBsl.issuerConfig;
              await zcapClient.write({
                url: `${smallBsl.statusId}/credentials/status`,
                capability: smallBsl.statusRootZcap,
                json: {
                  credentialId: verifiableCredential.id,
                  indexAllocator,
                  credentialStatus: verifiableCredential.credentialStatus,
                  status: true
                }
              });
            } catch(e) {
              error = e;
            }
            assertNoError(error);

            // force refresh of new SLC
            await zcapClient.write({
              url: `${statusInfo.statusListCredential}?refresh=true`,
              capability: smallBsl.statusRootZcap,
              json: {}
            });

            // check status of VC has changed
            ({status} = await helpers.getCredentialStatus(
              {verifiableCredential}));
            status.should.equal(true);
          }
        });

        it('issues VCs with limited lists', async function() {
          // two minutes to issue and rollover lists
          this.timeout(1000 * 60 * 2);

          const statusPurpose = 'revocation';

          // list length is 8, do two rollovers to hit list count capacity of 2
          const listLength = 8;
          for(let i = 0; i < (listLength * 2 + 1); ++i) {
            // first issue VC
            const credential = klona(mockTerseCredential);
            credential.id = `urn:uuid:${uuid()}`;
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            let verifiableCredential;
            try {
              ({data: {verifiableCredential}} = await zcapClient.write({
                url: `${smallTerseStatusList.issuerId}/credentials/issue`,
                capability: smallTerseStatusList.rootZcap,
                json: {credential, options: terseIssueOptions}
              }));
            } catch(e) {
              // max list count reached, expected at `listLength * 2` only
              if(e?.data?.name === 'QuotaExceededError') {
                i.should.equal(listLength * 2);
                return;
              }
              throw e;
            }

            // ensure TerseBitstringStatusEntry was added to VC
            should.exist(verifiableCredential.credentialStatus);
            verifiableCredential.credentialStatus.should.have.keys([
              'type', 'terseStatusListBaseUrl', 'terseStatusListIndex'
            ]);
            verifiableCredential.credentialStatus.type.should.equal(
              'TerseBitstringStatusListEntry');
            verifiableCredential.credentialStatus.terseStatusListIndex
              .should.be.a('number');

            // get VC status
            const statusInfo = await helpers.getCredentialStatus(
              {verifiableCredential, listLength, statusPurpose});
            let {status} = statusInfo;
            status.should.equal(false);

            // then revoke VC
            let error;
            try {
              const {statusListOptions: [{indexAllocator}]} =
                smallTerseStatusList.issuerConfig;
              await zcapClient.write({
                url: `${smallTerseStatusList.statusId}/credentials/status`,
                capability: smallTerseStatusList.statusRootZcap,
                json: {
                  credentialId: verifiableCredential.id,
                  indexAllocator,
                  credentialStatus: statusInfo.expandedCredentialStatus,
                  status: true
                }
              });
            } catch(e) {
              error = e;
            }
            assertNoError(error);

            // force refresh of new SLC
            await zcapClient.write({
              url: `${statusInfo.statusListCredential}?refresh=true`,
              capability: smallTerseStatusList.statusRootZcap,
              json: {}
            });

            // check status of VC has changed
            ({status} = await helpers.getCredentialStatus(
              {verifiableCredential, listLength, statusPurpose}));
            status.should.equal(true);
          }
        });
      });
    });
  }
});

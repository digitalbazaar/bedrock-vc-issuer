/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {createRequire} from 'node:module';
import {encode} from 'base64url-universal';
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
const mockCredentialV2 = require('./mock-credential-v2.json');
const mockTerseCredential = require('./mock-terse-credential.json');

describe('issue APIs', () => {
  const suiteNames = {
    Ed25519Signature2020: {
      algorithm: 'Ed25519',
      statusOptions: {
        suiteName: 'Ed25519Signature2020'
      }
    },
    'eddsa-rdfc-2022': {
      algorithm: 'Ed25519',
      statusOptions: {
        suiteName: 'eddsa-rdfc-2022'
      }
    },
    'ecdsa-rdfc-2019': {
      algorithm: ['P-256', 'P-384'],
      statusOptions: {
        suiteName: 'ecdsa-rdfc-2019'
      }
    },
    'ecdsa-sd-2023': {
      algorithm: ['P-256'],
      statusOptions: {
        suiteName: 'ecdsa-rdfc-2019'
      }
    },
    'ecdsa-xi-2023': {
      algorithm: ['P-256', 'P-384'],
      issueOptions: {
        extraInformation: 'abc'
      },
      statusOptions: {
        suiteName: 'ecdsa-rdfc-2019'
      }
    }
  };
  // list of suites to run the selective disclosure tests on
  const sdSuites = new Set(['ecdsa-sd-2023']);
  // list of suites to run extra information tests on
  const xiSuites = new Set(['ecdsa-xi-2023']);
  for(const suiteName in suiteNames) {
    const suiteInfo = suiteNames[suiteName];
    const {issueOptions, statusOptions} = suiteInfo;
    if(Array.isArray(suiteInfo.algorithm)) {
      for(const algorithm of suiteInfo.algorithm) {
        describeSuite({suiteName, algorithm, issueOptions, statusOptions});
      }
    } else {
      describeSuite({
        suiteName, algorithm: suiteInfo.algorithm, issueOptions, statusOptions
      });
    }
  }
  function describeSuite({suiteName, algorithm, issueOptions, statusOptions}) {
    const testDescription = `${suiteName}, algorithm: ${algorithm}`;
    const depOptions = {
      suiteOptions: {suiteName, algorithm, issueOptions, statusOptions}
    };
    describe(testDescription, function() {
      let capabilityAgent;
      let noStatusListIssuerId;
      let noStatusListIssuerRootZcap;
      let bslRevocationIssuerConfig;
      let bslRevocationIssuerId;
      let bslRevocationRootZcap;
      let bslRevocationStatusId;
      let bslRevocationStatusRootZcap;
      let bslSuspensionIssuerConfig;
      let bslSuspensionIssuerId;
      let bslSuspensionRootZcap;
      let bslSuspensionStatusId;
      let bslSuspensionStatusRootZcap;
      let smallBslIssuerConfig;
      let smallBslIssuerId;
      let smallBslRootZcap;
      let smallBslStatusId;
      let smallBslStatusRootZcap;
      let smallTerseStatusListIssuerConfig;
      let smallTerseStatusListIssuerId;
      let smallTerseStatusListRootZcap;
      let smallTerseStatusListStatusId;
      let smallTerseStatusListStatusRootZcap;
      let oauth2IssuerConfig;
      const zcaps = {};
      beforeEach(async () => {
        // provision dependencies
        ({capabilityAgent} = await helpers.provisionDependencies(depOptions));

        // create keystore for capability agent
        const keystoreAgent = await helpers.createKeystoreAgent(
          {capabilityAgent});
        // generate key for signing VCs (make it a did:key DID for simplicity)
        let assertionMethodKey;
        const publicAliasTemplate =
          'did:key:{publicKeyMultibase}#{publicKeyMultibase}';
        if(algorithm === 'P-256' || algorithm === 'P-384') {
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
        const {id: edvId} = edvConfig;
        zcaps.edv = await helpers.delegate({
          controller: serviceAgent.id,
          delegator: capabilityAgent,
          invocationTarget: edvId
        });
        const {keystoreId} = keystoreAgent;
        zcaps.hmac = await helpers.delegate({
          capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
          controller: serviceAgent.id,
          invocationTarget: hmac.id,
          delegator: capabilityAgent
        });
        zcaps.keyAgreementKey = await helpers.delegate({
          capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
          controller: serviceAgent.id,
          invocationTarget: keyAgreementKey.kmsId,
          delegator: capabilityAgent
        });
        zcaps.assertionMethod = await helpers
          .delegate({
            capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
            controller: serviceAgent.id,
            invocationTarget: assertionMethodKey.kmsId,
            delegator: capabilityAgent
          });

        // create issuer instance w/ no status list options
        const noStatusListIssuerConfig = await helpers.createIssuerConfig(
          {capabilityAgent, zcaps, suiteName});
        noStatusListIssuerId = noStatusListIssuerConfig.id;
        noStatusListIssuerRootZcap =
          `urn:zcap:root:${encodeURIComponent(noStatusListIssuerId)}`;

        // create issuer instance w/ status list 2021 status list options
        // w/ revocation status purpose
        {
          const {
            statusConfig,
            issuerCreateStatusListZcap
          } = await helpers.provisionDependencies(depOptions);
          const statusListOptions = [{
            type: 'BitstringStatusList',
            statusPurpose: 'revocation',
            zcapReferenceIds: {
              createCredentialStatusList: 'createCredentialStatusList'
            }
          }];
          const newZcaps = {
            ...zcaps,
            createCredentialStatusList: issuerCreateStatusListZcap
          };
          const issuerConfig = await helpers.createIssuerConfig({
            capabilityAgent, zcaps: newZcaps, statusListOptions, suiteName
          });
          bslRevocationIssuerConfig = issuerConfig;
          bslRevocationIssuerId = issuerConfig.id;
          bslRevocationRootZcap =
            `urn:zcap:root:${encodeURIComponent(issuerConfig.id)}`;
          bslRevocationStatusId = statusConfig.id;
          bslRevocationStatusRootZcap =
            `urn:zcap:root:${encodeURIComponent(statusConfig.id)}`;
        }

        // create issuer instance w/ status list 2021 status list options
        // w/ suspension status purpose
        {
          const {
            statusConfig,
            issuerCreateStatusListZcap
          } = await helpers.provisionDependencies(depOptions);
          const statusListOptions = [{
            type: 'BitstringStatusList',
            statusPurpose: 'suspension',
            zcapReferenceIds: {
              createCredentialStatusList: 'createCredentialStatusList'
            }
          }];
          const newZcaps = {
            ...zcaps,
            createCredentialStatusList: issuerCreateStatusListZcap
          };
          const issuerConfig = await helpers.createIssuerConfig({
            capabilityAgent, zcaps: newZcaps, statusListOptions, suiteName
          });
          bslSuspensionIssuerConfig = issuerConfig;
          bslSuspensionIssuerId = issuerConfig.id;
          bslSuspensionRootZcap =
            `urn:zcap:root:${encodeURIComponent(issuerConfig.id)}`;
          bslSuspensionStatusId = statusConfig.id;
          bslSuspensionStatusRootZcap =
            `urn:zcap:root:${encodeURIComponent(statusConfig.id)}`;
        }

        // create issuer instance w/ small status list
        {
          const {
            statusConfig,
            issuerCreateStatusListZcap
          } = await helpers.provisionDependencies(depOptions);
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
          const newZcaps = {
            ...zcaps,
            createCredentialStatusList: issuerCreateStatusListZcap
          };
          const issuerConfig = await helpers.createIssuerConfig({
            capabilityAgent, zcaps: newZcaps, statusListOptions, suiteName
          });
          smallBslIssuerConfig = issuerConfig;
          smallBslIssuerId = issuerConfig.id;
          smallBslRootZcap =
            `urn:zcap:root:${encodeURIComponent(issuerConfig.id)}`;
          smallBslStatusId = statusConfig.id;
          smallBslStatusRootZcap =
            `urn:zcap:root:${encodeURIComponent(statusConfig.id)}`;
        }

        // create issuer instance w/ small terse status list
        {
          const {
            statusConfig,
            issuerCreateStatusListZcap
          } = await helpers.provisionDependencies(depOptions);
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
          const newZcaps = {
            ...zcaps,
            createCredentialStatusList: issuerCreateStatusListZcap
          };
          const issuerConfig = await helpers.createIssuerConfig({
            capabilityAgent, zcaps: newZcaps, statusListOptions, suiteName
          });
          smallTerseStatusListIssuerConfig = issuerConfig;
          smallTerseStatusListIssuerId = issuerConfig.id;
          smallTerseStatusListRootZcap =
            `urn:zcap:root:${encodeURIComponent(issuerConfig.id)}`;
          smallTerseStatusListStatusId = statusConfig.id;
          smallTerseStatusListStatusRootZcap =
            `urn:zcap:root:${encodeURIComponent(statusConfig.id)}`;

          // insert example context for issuing VCs w/terse status entries
          const {
            testBarcodeCredentialContextUrl,
            testBarcodeCredentialContext
          } = mockData;
          const client = helpers.createZcapClient({capabilityAgent});
          const url = `${smallTerseStatusListIssuerId}/contexts`;
          await client.write({
            url, json: {
              id: testBarcodeCredentialContextUrl,
              context: testBarcodeCredentialContext
            },
            capability: smallTerseStatusListRootZcap
          });
        }

        // create issuer instance w/ oauth2-based authz
        oauth2IssuerConfig = await helpers.createIssuerConfig(
          {capabilityAgent, zcaps, oauth2: true, suiteName});
      });
      describe('/credentials/issue', () => {
        it('issues a valid credential w/no "credentialStatus"', async () => {
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
                options: issueOptions
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
          verifiableCredential.proof.should.be.an('object');
        });
        it('issues a VC 2.0 credential w/no "credentialStatus"', async () => {
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
                  ...issueOptions,
                  mandatoryPointers: ['issuer']
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
          verifiableCredential.proof.should.be.an('object');
        });

        it('fails to issue a valid credential', async () => {
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
        it('issues a valid credential w/oauth2 w/root scope', async () => {
          const credential = klona(mockCredential);
          let error;
          let result;
          try {
            const configId = oauth2IssuerConfig.id;
            const url = `${configId}/credentials/issue`;
            const accessToken = await helpers.getOAuth2AccessToken(
              {configId, action: 'write', target: '/'});
            result = await httpClient.post(url, {
              agent,
              headers: {authorization: `Bearer ${accessToken}`},
              json: {credential, options: issueOptions}
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
          verifiableCredential.proof.should.be.an('object');
        });
        it('issues a valid credential w/oauth2 w/credentials scope',
          async () => {
            const credential = klona(mockCredential);
            let error;
            let result;
            try {
              const configId = oauth2IssuerConfig.id;
              const url = `${configId}/credentials/issue`;
              const accessToken = await helpers.getOAuth2AccessToken(
                {configId, action: 'write', target: '/credentials'});
              result = await httpClient.post(url, {
                agent,
                headers: {authorization: `Bearer ${accessToken}`},
                json: {credential, options: issueOptions}
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
            verifiableCredential.proof.should.be.an('object');
          });
        it('issues a valid credential w/oauth2 w/targeted scope', async () => {
          const credential = klona(mockCredential);
          let error;
          let result;
          try {
            const configId = oauth2IssuerConfig.id;
            const url = `${configId}/credentials/issue`;
            const accessToken = await helpers.getOAuth2AccessToken(
              {configId, action: 'write', target: '/credentials/issue'});
            result = await httpClient.post(url, {
              agent,
              headers: {authorization: `Bearer ${accessToken}`},
              json: {credential, options: issueOptions}
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
          verifiableCredential.proof.should.be.an('object');
        });
        it('fails to issue a valid credential w/bad action scope', async () => {
          const credential = klona(mockCredential);
          let error;
          let result;
          try {
            const configId = oauth2IssuerConfig.id;
            const url = `${configId}/credentials/issue`;
            const accessToken = await helpers.getOAuth2AccessToken(
              // wrong action: `read`
              {configId, action: 'read', target: '/credentials/issue'});
            result = await httpClient.post(url, {
              agent,
              headers: {authorization: `Bearer ${accessToken}`},
              json: {credential, options: issueOptions}
            });
          } catch(e) {
            error = e;
          }
          should.exist(error);
          should.not.exist(result);
          error.status.should.equal(403);
          error.data.type.should.equal('NotAllowedError');
          should.exist(error.data.cause);
          should.exist(error.data.cause.details);
          should.exist(error.data.cause.details.code);
          error.data.cause.details.code.should.equal(
            'ERR_JWT_CLAIM_VALIDATION_FAILED');
          should.exist(error.data.cause.details.claim);
          error.data.cause.details.claim.should.equal('scope');
        });
        it('fails to issue a valid credential w/bad path scope', async () => {
          const credential = klona(mockCredential);
          let error;
          let result;
          try {
            const configId = oauth2IssuerConfig.id;
            const url = `${configId}/credentials/issue`;
            const accessToken = await helpers.getOAuth2AccessToken(
              // wrong path: `/foo`
              {configId, action: 'write', target: '/foo'});
            result = await httpClient.post(url, {
              agent,
              headers: {authorization: `Bearer ${accessToken}`},
              json: {credential, options: issueOptions}
            });
          } catch(e) {
            error = e;
          }
          should.exist(error);
          should.not.exist(result);
          error.status.should.equal(403);
          error.data.type.should.equal('NotAllowedError');
          should.exist(error.data.cause);
          should.exist(error.data.cause.details);
          should.exist(error.data.cause.details.code);
          error.data.cause.details.code.should.equal(
            'ERR_JWT_CLAIM_VALIDATION_FAILED');
          should.exist(error.data.cause.details.claim);
          error.data.cause.details.claim.should.equal('scope');
        });
        it('issues a valid credential w/ "credentialStatus" and ' +
          'suspension status purpose', async () => {
          const credential = klona(mockCredential);
          let error;
          let result;
          try {
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            result = await zcapClient.write({
              url: `${bslSuspensionIssuerId}/credentials/issue`,
              capability: bslSuspensionRootZcap,
              json: {
                credential,
                options: issueOptions
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
          should.exist(verifiableCredential.credentialStatus);
          should.exist(verifiableCredential.proof);
          verifiableCredential.proof.should.be.an('object');
        });
        it('fails when trying to issue a duplicate credential', async () => {
          const zcapClient = helpers.createZcapClient({capabilityAgent});

          // issue VC (should succeed)
          let credential = klona(mockCredential);
          let error;
          let result;
          try {
            result = await zcapClient.write({
              url: `${bslRevocationIssuerId}/credentials/issue`,
              capability: bslRevocationRootZcap,
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
              url: `${bslRevocationIssuerId}/credentials/issue`,
              capability: bslRevocationRootZcap,
              json: {credential, options: issueOptions}
            });
          } catch(e) {
            error = e;
          }
          should.exist(error);
          error.data.type.should.equal('DuplicateError');
        });
        // selective disclosure specific tests here
        if(sdSuites.has(suiteName)) {
          it('issues a valid credential w/ "options.mandatoryPointers"',
            async () => {
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
                      ...issueOptions,
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
              should.exist(verifiableCredential.issuanceDate);
              should.exist(verifiableCredential.credentialSubject);
              verifiableCredential.credentialSubject.should.be.an('object');
              should.not.exist(verifiableCredential.credentialStatus);
              should.exist(verifiableCredential.proof);
              verifiableCredential.proof.should.be.an('object');
            });
          it('fails to issue a valid credential w/ invalid ' +
            '"options.mandatoryPointers"', async () => {
            let error;
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
                    mandatoryPointers: ['/nonExistentPointer']
                  }
                }
              });
            } catch(e) {
              error = e;
            }
            should.exist(error);
            error.data.type.should.equal('OperationError');
          });
        }
        // extra information tests
        if(xiSuites.has(suiteName)) {
          it('issues a valid credential w/ "options.extraInformation"',
            async () => {
              const credential = klona(mockCredential);
              let error;
              let result;
              try {
                const zcapClient = helpers.createZcapClient({capabilityAgent});
                const extraInformationBytes = new Uint8Array([
                  12, 52, 75, 63, 74, 85, 21, 5, 62, 10
                ]);
                const extraInformationEncoded = encode(extraInformationBytes);
                result = await zcapClient.write({
                  url: `${noStatusListIssuerId}/credentials/issue`,
                  capability: noStatusListIssuerRootZcap,
                  json: {
                    credential,
                    options: {
                      ...issueOptions,
                      extraInformation: extraInformationEncoded
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
              verifiableCredential.proof.should.be.an('object');
            });
          it('fails to issue a valid credential w/ invalid ' +
            '"options.extraInformation"', async () => {
            let error;
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
                    extraInformation: ['notAString']
                  }
                }
              });
            } catch(e) {
              error = e;
            }
            should.exist(error);
            // how to throw OperationError not ValidationError here? necessary?
            error.data.type.should.equal('ValidationError');
          });
        }
      });

      describe('/credentials/status', () => {
        it('updates a BitstringStatusList revocation credential status',
          async () => {
            // first issue VC
            const credential = klona(mockCredential);
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            const {data: {verifiableCredential}} = await zcapClient.write({
              url: `${bslRevocationIssuerId}/credentials/issue`,
              capability: bslRevocationRootZcap,
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
                bslRevocationIssuerConfig;
              await zcapClient.write({
                url: `${bslRevocationStatusId}/credentials/status`,
                capability: bslRevocationStatusRootZcap,
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
              capability: bslRevocationStatusRootZcap,
              json: {}
            });

            // check status of VC has changed
            ({status} = await helpers.getCredentialStatus(
              {verifiableCredential}));
            status.should.equal(true);
          });
        it('updates a BitstringStatusList suspension credential status',
          async () => {
          // first issue VC
            const credential = klona(mockCredential);
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            const {data: {verifiableCredential}} = await zcapClient.write({
              url: `${bslSuspensionIssuerId}/credentials/issue`,
              capability: bslSuspensionRootZcap,
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
                bslSuspensionIssuerConfig;
              await zcapClient.write({
                url: `${bslSuspensionStatusId}/credentials/status`,
                capability: bslSuspensionStatusRootZcap,
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
              capability: bslSuspensionStatusRootZcap,
              json: {}
            });

            // check status of VC has changed
            ({status} = await helpers.getCredentialStatus(
              {verifiableCredential}));
            status.should.equal(true);
          });
      });

      describe('status scaling /credentials/issue', () => {
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
              url: `${smallBslIssuerId}/credentials/issue`,
              capability: smallBslRootZcap,
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
                smallBslIssuerConfig;
              await zcapClient.write({
                url: `${smallBslStatusId}/credentials/status`,
                capability: smallBslStatusRootZcap,
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
              capability: smallBslStatusRootZcap,
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
          let terseIssueOptions = issueOptions;
          if(sdSuites.has(depOptions.suiteOptions.suiteName)) {
            terseIssueOptions = {mandatoryPointers: ['issuer']};
          }

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
                url: `${smallTerseStatusListIssuerId}/credentials/issue`,
                capability: smallTerseStatusListRootZcap,
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
              {verifiableCredential, statusPurpose, listLength});
            let {status} = statusInfo;
            status.should.equal(false);

            // then revoke VC
            let error;
            try {
              const {statusListOptions: [{indexAllocator}]} =
                smallTerseStatusListIssuerConfig;
              await zcapClient.write({
                url: `${smallTerseStatusListStatusId}/credentials/status`,
                capability: smallTerseStatusListStatusRootZcap,
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
              capability: smallTerseStatusListStatusRootZcap,
              json: {}
            });

            // check status of VC has changed
            ({status} = await helpers.getCredentialStatus(
              {verifiableCredential, statusPurpose, listLength}));
            status.should.equal(true);
          }
        });
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
            url: `${bslRevocationIssuerId}/credentials/issue`,
            capability: bslRevocationRootZcap,
            json: {credential: credential1, options: issueOptions}
          });

          const vc1StatusId = vc1.credentialStatus.id;

          // now issue second VC (should succeed and process the
          const credential2 = klona(mockCredential);
          credential2.id = 'urn:id2';
          const {data: {verifiableCredential: vc2}} = await zcapClient.write({
            url: `${bslRevocationIssuerId}/credentials/issue`,
            capability: bslRevocationRootZcap,
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
              url: `${bslRevocationIssuerId}/credentials/issue`,
              capability: bslRevocationRootZcap,
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
              url: `${bslRevocationIssuerId}/credentials/issue`,
              capability: bslRevocationRootZcap,
              json: {credential, options: issueOptions}
            });
          } catch(e) {
            error = e;
          }
          should.exist(error);
          error.data.type.should.equal('DuplicateError');
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
              url: `${smallBslIssuerId}/credentials/issue`,
              capability: smallBslRootZcap,
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
                smallBslIssuerConfig;
              await zcapClient.write({
                url: `${smallBslStatusId}/credentials/status`,
                capability: smallBslStatusRootZcap,
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
              capability: smallBslStatusRootZcap,
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
          let terseIssueOptions = issueOptions;
          if(sdSuites.has(depOptions.suiteOptions.suiteName)) {
            terseIssueOptions = {mandatoryPointers: ['issuer']};
          }

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
                url: `${smallTerseStatusListIssuerId}/credentials/issue`,
                capability: smallTerseStatusListRootZcap,
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
                smallTerseStatusListIssuerConfig;
              await zcapClient.write({
                url: `${smallTerseStatusListStatusId}/credentials/status`,
                capability: smallTerseStatusListStatusRootZcap,
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
              capability: smallTerseStatusListStatusRootZcap,
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

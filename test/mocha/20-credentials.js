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
      },
      terseIssueOptions: {mandatoryPointers: ['/issuer']}
    },
    'ecdsa-xi-2023': {
      algorithm: ['P-256', 'P-384'],
      issueOptions: {
        extraInformation: 'abc'
      },
      statusOptions: {
        suiteName: 'ecdsa-rdfc-2019'
      }
    },
    'bbs-2023': {
      algorithm: ['Bls12381G2'],
      statusOptions: {
        // sign status list with simple ECDSA
        algorithm: 'P-256',
        suiteName: 'ecdsa-rdfc-2019'
      },
      terseIssueOptions: {mandatoryPointers: ['/issuer']}
    }
  };
  // list of suites to run the selective disclosure tests on
  const sdSuites = new Set(['ecdsa-sd-2023', 'bbs-2023']);
  // list of suites to run extra information tests on
  const xiSuites = new Set(['ecdsa-xi-2023']);
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
      let bslRevocationSuspensionIssuerConfig;
      let bslRevocationSuspensionIssuerId;
      let bslRevocationSuspensionRootZcap;
      let bslRevocationSuspensionStatusId;
      let bslRevocationSuspensionStatusRootZcap;
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
      let terseMultistatusIssuerConfig;
      let terseMultistatusIssuerId;
      let terseMultistatusRootZcap;
      let terseMultistatusStatusId;
      let terseMultistatusStatusRootZcap;
      let oauth2IssuerConfig;
      beforeEach(async () => {
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
          capability: 'urn:zcap:root:' + encodeURIComponent(
            helpers.parseKeystoreId(assertionMethodKey.kmsId)),
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

        // create issuer instance w/ bitstring status list options
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

        // create issuer instance w/ bitstring status list status list options
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

        // create issuer instance w/ bitstring status list options
        // w/ both revocation and suspension status purposes
        {
          const {
            statusConfig,
            issuerCreateStatusListZcap
          } = await helpers.provisionDependencies(depOptions);
          const statusListOptions = [{
            type: 'BitstringStatusList',
            statusPurpose: ['revocation', 'suspension'],
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
          bslRevocationSuspensionIssuerConfig = issuerConfig;
          bslRevocationSuspensionIssuerId = issuerConfig.id;
          bslRevocationSuspensionRootZcap =
            `urn:zcap:root:${encodeURIComponent(issuerConfig.id)}`;
          bslRevocationSuspensionStatusId = statusConfig.id;
          bslRevocationSuspensionStatusRootZcap =
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

        // create issuer instance w/ terse bitstring status list options
        // w/ revocation AND suspension status purpose
        {
          const {
            statusConfig,
            issuerCreateStatusListZcap
          } = await helpers.provisionDependencies(depOptions);
          const statusListOptions = [{
            type: 'TerseBitstringStatusList',
            statusPurpose: ['revocation', 'suspension'],
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
          terseMultistatusIssuerConfig = issuerConfig;
          terseMultistatusIssuerId = issuerConfig.id;
          terseMultistatusRootZcap =
            `urn:zcap:root:${encodeURIComponent(issuerConfig.id)}`;
          terseMultistatusStatusId = statusConfig.id;
          terseMultistatusStatusRootZcap =
            `urn:zcap:root:${encodeURIComponent(statusConfig.id)}`;
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
                  ...issueOptions
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
        it('issues a valid credential w/ terse "credentialStatus" for ' +
          'both revocation and suspension status purpose', async () => {
          const credential = klona(mockTerseCredential);
          let error;
          let result;
          try {
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            result = await zcapClient.write({
              url: `${terseMultistatusIssuerId}/credentials/issue`,
              capability: terseMultistatusRootZcap,
              json: {
                credential,
                options: terseIssueOptions
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
          should.exist(verifiableCredential.type);
          should.exist(verifiableCredential.credentialStatus);
          verifiableCredential.credentialStatus.should.have.keys([
            'type', 'terseStatusListBaseUrl', 'terseStatusListIndex'
          ]);
          verifiableCredential.credentialStatus.type.should.equal(
            'TerseBitstringStatusListEntry');
          verifiableCredential.credentialStatus.terseStatusListIndex
            .should.be.a('number');
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
                url: `${bslRevocationIssuerId}/credentials/issue`,
                capability: bslRevocationRootZcap,
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
                url: `${bslRevocationIssuerId}/credentials/issue`,
                capability: bslRevocationRootZcap,
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
                url: `${bslRevocationIssuerId}/credentials/issue`,
                capability: bslRevocationRootZcap,
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
        it('updates BitstringStatusList revocation+suspension status',
          async () => {
            // first issue VC
            const credential = klona(mockCredential);
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            const {data: {verifiableCredential}} = await zcapClient.write({
              url: `${bslRevocationSuspensionIssuerId}/credentials/issue`,
              capability: bslRevocationSuspensionRootZcap,
              json: {credential, options: issueOptions}
            });

            {
              // get VC suspension status
              const statusInfo = await helpers.getCredentialStatus(
                {verifiableCredential, statusPurpose: 'suspension'});
              let {status} = statusInfo;
              status.should.equal(false);

              // then suspend VC
              let error;
              try {
                const {statusListOptions: [{indexAllocator}]} =
                  bslRevocationSuspensionIssuerConfig;
                await zcapClient.write({
                  url: `${bslRevocationSuspensionStatusId}/credentials/status`,
                  capability: bslRevocationSuspensionStatusRootZcap,
                  json: {
                    credentialId: verifiableCredential.id,
                    indexAllocator,
                    credentialStatus: statusInfo.credentialStatus,
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
                capability: bslRevocationSuspensionStatusRootZcap,
                json: {}
              });

              // check status of VC has changed
              ({status} = await helpers.getCredentialStatus(
                {verifiableCredential, statusPurpose: 'suspension'}));
              status.should.equal(true);
            }

            {
              // get VC revocation status
              const statusInfo = await helpers.getCredentialStatus(
                {verifiableCredential, statusPurpose: 'revocation'});
              let {status} = statusInfo;
              status.should.equal(false);

              // then revoke VC
              let error;
              try {
                const {statusListOptions: [{indexAllocator}]} =
                  bslRevocationSuspensionIssuerConfig;
                await zcapClient.write({
                  url: `${bslRevocationSuspensionStatusId}/credentials/status`,
                  capability: bslRevocationSuspensionStatusRootZcap,
                  json: {
                    credentialId: verifiableCredential.id,
                    indexAllocator,
                    credentialStatus: statusInfo.credentialStatus,
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
                capability: bslRevocationSuspensionStatusRootZcap,
                json: {}
              });

              // check status of VC has changed
              ({status} = await helpers.getCredentialStatus(
                {verifiableCredential, statusPurpose: 'revocation'}));
              status.should.equal(true);
            }
          });

        it('updates multiple TerseBitstringStatusList statuses',
          async () => {
            // first issue VC
            const credential = klona(mockTerseCredential);
            const credentialId = `urn:uuid:${uuid()}`;
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            const {data: {verifiableCredential}} = await zcapClient.write({
              url: `${terseMultistatusIssuerId}/credentials/issue`,
              capability: terseMultistatusRootZcap,
              json: {
                credential,
                options: {...terseIssueOptions, credentialId}
              }
            });

            // get VC statuses
            const listLength = 131072;
            const revocationStatusInfo = await helpers.getCredentialStatus(
              {verifiableCredential, statusPurpose: 'revocation', listLength});
            revocationStatusInfo.status.should.equal(false);
            const suspensionStatusInfo = await helpers.getCredentialStatus(
              {verifiableCredential, statusPurpose: 'suspension', listLength});
            suspensionStatusInfo.status.should.equal(false);

            // then revoke VC
            {
              let error;
              try {
                const {statusListOptions: [{indexAllocator}]} =
                  terseMultistatusIssuerConfig;
                await zcapClient.write({
                  url: `${terseMultistatusStatusId}/credentials/status`,
                  capability: terseMultistatusStatusRootZcap,
                  json: {
                    credentialId,
                    indexAllocator,
                    credentialStatus: revocationStatusInfo
                      .expandedCredentialStatus,
                    status: true
                  }
                });
              } catch(e) {
                error = e;
              }
              assertNoError(error);
            }

            // then suspend VC
            {
              let error;
              try {
                const {statusListOptions: [{indexAllocator}]} =
                  terseMultistatusIssuerConfig;
                await zcapClient.write({
                  url: `${terseMultistatusStatusId}/credentials/status`,
                  capability: terseMultistatusStatusRootZcap,
                  json: {
                    credentialId,
                    indexAllocator,
                    credentialStatus: suspensionStatusInfo
                      .expandedCredentialStatus,
                    status: true
                  }
                });
              } catch(e) {
                error = e;
              }
              assertNoError(error);
            }

            // force refresh of new SLCs
            await zcapClient.write({
              url: `${revocationStatusInfo.statusListCredential}?refresh=true`,
              capability: terseMultistatusStatusRootZcap,
              json: {}
            });
            await zcapClient.write({
              url: `${suspensionStatusInfo.statusListCredential}?refresh=true`,
              capability: terseMultistatusStatusRootZcap,
              json: {}
            });

            // check statuses of VC have changed
            const newRevocationStatus = await helpers.getCredentialStatus(
              {verifiableCredential, statusPurpose: 'revocation', listLength});
            newRevocationStatus.status.should.equal(true);
            const newSuspensionStatus = await helpers.getCredentialStatus(
              {verifiableCredential, statusPurpose: 'revocation', listLength});
            newSuspensionStatus.status.should.equal(true);
          });
      });

      describe('status scaling /credentials/issue', () => {
        // some of these tests take considerable time and do not change with
        // different cryptosuites, so run them with just one suite
        if(depOptions.suiteOptions.suiteName !== 'eddsa-rdfc-2022') {
          return;
        }
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
        // some of these tests take considerable time and do not change with
        // different cryptosuites, so run them with just one suite
        if(depOptions.suiteOptions.suiteName !== 'eddsa-rdfc-2022') {
          return;
        }

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
                url: `${bslRevocationIssuerId}/credentials/issue`,
                capability: bslRevocationRootZcap,
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
                url: `${bslRevocationIssuerId}/credentials/issue`,
                capability: bslRevocationRootZcap,
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
                url: `${bslRevocationIssuerId}/credentials/issue`,
                capability: bslRevocationRootZcap,
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

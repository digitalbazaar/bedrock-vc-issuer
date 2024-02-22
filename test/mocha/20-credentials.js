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

describe('issue APIs', () => {
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
    }
  };
  // list of suites to run the selective disclosure tests on
  const sdSuites = new Set(['ecdsa-sd-2023']);
  for(const suiteName in suiteNames) {
    const suiteInfo = suiteNames[suiteName];
    if(Array.isArray(suiteInfo.algorithm)) {
      for(const algorithm of suiteInfo.algorithm) {
        describeSuite({suiteName, algorithm});
      }
    } else {
      describeSuite({suiteName, algorithm: suiteInfo.algorithm});
    }
  }
  function describeSuite({suiteName, algorithm}) {
    const testDescription = `${suiteName}, algorithm: ${algorithm}`;
    const depOptions = {suiteOptions: {suiteName, algorithm}};
    describe(testDescription, function() {
      let capabilityAgent;
      let noStatusListIssuerId;
      let noStatusListIssuerRootZcap;
      let sl2021RevocationIssuerId;
      let sl2021RevocationRootZcap;
      let sl2021RevocationStatusId;
      let sl2021RevocationStatusRootZcap;
      let sl2021SuspensionIssuerId;
      let sl2021SuspensionRootZcap;
      let sl2021SuspensionStatusId;
      let sl2021SuspensionStatusRootZcap;
      let smallStatusListIssuerId;
      let smallStatusListRootZcap;
      let smallStatusListStatusId;
      let smallStatusListStatusRootZcap;
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
            type: 'StatusList2021',
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
          sl2021RevocationIssuerId = issuerConfig.id;
          sl2021RevocationRootZcap =
            `urn:zcap:root:${encodeURIComponent(issuerConfig.id)}`;
          sl2021RevocationStatusId = statusConfig.id;
          sl2021RevocationStatusRootZcap =
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
            type: 'StatusList2021',
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
          sl2021SuspensionIssuerId = issuerConfig.id;
          sl2021SuspensionRootZcap =
            `urn:zcap:root:${encodeURIComponent(issuerConfig.id)}`;
          sl2021SuspensionStatusId = statusConfig.id;
          sl2021SuspensionStatusRootZcap =
            `urn:zcap:root:${encodeURIComponent(statusConfig.id)}`;
        }

        // create issuer instance w/ small status list
        {
          const {
            statusConfig,
            issuerCreateStatusListZcap
          } = await helpers.provisionDependencies(depOptions);
          const statusListOptions = [{
            type: 'StatusList2021',
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
          smallStatusListIssuerId = issuerConfig.id;
          smallStatusListRootZcap =
            `urn:zcap:root:${encodeURIComponent(issuerConfig.id)}`;
          smallStatusListStatusId = statusConfig.id;
          smallStatusListStatusRootZcap =
            `urn:zcap:root:${encodeURIComponent(statusConfig.id)}`;
        }

        // create issuer instance w/ small terse status list
        {
          const {
            statusConfig,
            issuerCreateStatusListZcap
          } = await helpers.provisionDependencies(depOptions);
          const statusListOptions = [{
            // FIXME: `TerseBitstringStatusList`
            type: 'StatusList2021',
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
          smallTerseStatusListIssuerId = issuerConfig.id;
          smallTerseStatusListRootZcap =
            `urn:zcap:root:${encodeURIComponent(issuerConfig.id)}`;
          smallTerseStatusListStatusId = statusConfig.id;
          smallTerseStatusListStatusRootZcap =
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
                credential
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
              json: {credential}
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
              json: {credential}
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
        it('issues a valid credential w/ SL 2021 "credentialStatus" and ' +
          'suspension status purpose', async () => {
          const credential = klona(mockCredential);
          let error;
          let result;
          try {
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            result = await zcapClient.write({
              url: `${sl2021SuspensionIssuerId}/credentials/issue`,
              capability: sl2021SuspensionRootZcap,
              json: {
                credential
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
              url: `${sl2021RevocationIssuerId}/credentials/issue`,
              capability: sl2021RevocationRootZcap,
              json: {credential}
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
              url: `${sl2021RevocationIssuerId}/credentials/issue`,
              capability: sl2021RevocationRootZcap,
              json: {credential}
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
      });

      // FIXME: consider removal as only this tests the status service which is
      // now separate
      describe('/credentials/status', () => {
        it('updates a StatusList2021 revocation credential status',
          async () => {
            // first issue VC
            const credential = klona(mockCredential);
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            const {data: {verifiableCredential}} = await zcapClient.write({
              url: `${sl2021RevocationIssuerId}/credentials/issue`,
              capability: sl2021RevocationRootZcap,
              json: {credential}
            });

            // get VC status
            const statusInfo = await helpers.getCredentialStatus(
              {verifiableCredential});
            let {status} = statusInfo;
            status.should.equal(false);

            // then revoke VC
            let error;
            try {
              await zcapClient.write({
                url: `${sl2021RevocationStatusId}/credentials/status`,
                capability: sl2021RevocationStatusRootZcap,
                json: {
                  credentialId: verifiableCredential.id,
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
              capability: sl2021RevocationStatusRootZcap,
              json: {}
            });

            // check status of VC has changed
            ({status} = await helpers.getCredentialStatus(
              {verifiableCredential}));
            status.should.equal(true);
          });
        it('updates a StatusList2021 suspension credential status',
          async () => {
          // first issue VC
            const credential = klona(mockCredential);
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            const {data: {verifiableCredential}} = await zcapClient.write({
              url: `${sl2021SuspensionIssuerId}/credentials/issue`,
              capability: sl2021SuspensionRootZcap,
              json: {credential}
            });

            // get VC status
            const statusInfo = await helpers.getCredentialStatus(
              {verifiableCredential});
            let {status} = statusInfo;
            status.should.equal(false);

            // then revoke VC
            let error;
            try {
              await zcapClient.write({
                url: `${sl2021SuspensionStatusId}/credentials/status`,
                capability: sl2021SuspensionStatusRootZcap,
                json: {
                  credentialId: verifiableCredential.id,
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
              capability: sl2021SuspensionStatusRootZcap,
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

          // list size is 8, do two rollovers
          const listSize = 8;
          for(let i = 0; i < (listSize * 2 + 1); ++i) {
            // first issue VC
            const credential = klona(mockCredential);
            credential.id = `urn:uuid:${uuid()}`;
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            const {data: {verifiableCredential}} = await zcapClient.write({
              url: `${smallStatusListIssuerId}/credentials/issue`,
              capability: smallStatusListRootZcap,
              json: {credential}
            });

            // get VC status
            const statusInfo = await helpers.getCredentialStatus(
              {verifiableCredential});
            let {status} = statusInfo;
            status.should.equal(false);

            // then revoke VC
            let error;
            try {
              await zcapClient.write({
                url: `${smallStatusListStatusId}/credentials/status`,
                capability: smallStatusListStatusRootZcap,
                json: {
                  credentialId: verifiableCredential.id,
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
              capability: smallStatusListStatusRootZcap,
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

          // list size is 8, do two rollovers to hit list count capacity of 2
          const listSize = 8;
          for(let i = 0; i < (listSize * 2 + 1); ++i) {
            // first issue VC
            const credential = klona(mockCredential);
            credential.id = `urn:uuid:${uuid()}`;
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            let verifiableCredential;
            try {
              ({data: {verifiableCredential}} = await zcapClient.write({
                url: `${smallTerseStatusListIssuerId}/credentials/issue`,
                capability: smallTerseStatusListRootZcap,
                json: {credential}
              }));
            } catch(e) {
              // max list count reached, expected at `listSize * 2` only
              if(e?.data?.name === 'QuotaExceededError') {
                i.should.equal(listSize * 2);
                return;
              }
              throw e;
            }

            // get VC status
            // FIXME: needs to include `indexAllocator` as TBD property
            const statusInfo = await helpers.getCredentialStatus(
              {verifiableCredential});
            let {status} = statusInfo;
            status.should.equal(false);

            // then revoke VC
            let error;
            try {
              await zcapClient.write({
                url: `${smallTerseStatusListStatusId}/credentials/status`,
                capability: smallTerseStatusListStatusRootZcap,
                json: {
                  credentialId: verifiableCredential.id,
                  // FIXME: needs to include `indexAllocator`
                  // FIXME: `BitstringStatusListEntry`
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
              capability: smallTerseStatusListStatusRootZcap,
              json: {}
            });

            // check status of VC has changed
            ({status} = await helpers.getCredentialStatus(
              {verifiableCredential}));
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
            url: `${sl2021RevocationIssuerId}/credentials/issue`,
            capability: sl2021RevocationRootZcap,
            json: {credential: credential1}
          });

          const vc1StatusId = vc1.credentialStatus.id;

          // now issue second VC (should succeed and process the
          const credential2 = klona(mockCredential);
          credential2.id = 'urn:id2';
          const {data: {verifiableCredential: vc2}} = await zcapClient.write({
            url: `${sl2021RevocationIssuerId}/credentials/issue`,
            capability: sl2021RevocationRootZcap,
            json: {credential: credential2}
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
              url: `${sl2021RevocationIssuerId}/credentials/issue`,
              capability: sl2021RevocationRootZcap,
              json: {credential}
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
              url: `${sl2021RevocationIssuerId}/credentials/issue`,
              capability: sl2021RevocationRootZcap,
              json: {credential}
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

          // list size is 8, do two rollovers
          const listSize = 8;
          for(let i = 0; i < (listSize * 2 + 1); ++i) {
            // first issue VC
            const credential = klona(mockCredential);
            credential.id = `urn:uuid:${uuid()}`;
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            const {data: {verifiableCredential}} = await zcapClient.write({
              url: `${smallStatusListIssuerId}/credentials/issue`,
              capability: smallStatusListRootZcap,
              json: {credential}
            });

            // get VC status
            const statusInfo = await helpers.getCredentialStatus(
              {verifiableCredential});
            let {status} = statusInfo;
            status.should.equal(false);

            // then revoke VC
            let error;
            try {
              await zcapClient.write({
                url: `${smallStatusListStatusId}/credentials/status`,
                capability: smallStatusListStatusRootZcap,
                json: {
                  credentialId: verifiableCredential.id,
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
              capability: smallStatusListStatusRootZcap,
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

          // list size is 8, do two rollovers to hit list count capacity of 2
          const listSize = 8;
          for(let i = 0; i < (listSize * 2 + 1); ++i) {
            // first issue VC
            const credential = klona(mockCredential);
            credential.id = `urn:uuid:${uuid()}`;
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            let verifiableCredential;
            try {
              ({data: {verifiableCredential}} = await zcapClient.write({
                url: `${smallTerseStatusListIssuerId}/credentials/issue`,
                capability: smallTerseStatusListRootZcap,
                json: {credential}
              }));
            } catch(e) {
              // max list count reached, expected at `listSize * 2` only
              if(e?.data?.name === 'QuotaExceededError') {
                i.should.equal(listSize * 2);
                return;
              }
              throw e;
            }

            // get VC status
            // FIXME: needs to include `indexAllocator` as TBD property
            const statusInfo = await helpers.getCredentialStatus(
              {verifiableCredential});
            let {status} = statusInfo;
            status.should.equal(false);

            // then revoke VC
            let error;
            try {
              await zcapClient.write({
                url: `${smallTerseStatusListStatusId}/credentials/status`,
                capability: smallTerseStatusListStatusRootZcap,
                json: {
                  credentialId: verifiableCredential.id,
                  // FIXME: needs to include `indexAllocator`
                  // FIXME: `BitstringStatusListEntry`
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
              capability: smallTerseStatusListStatusRootZcap,
              json: {}
            });

            // check status of VC has changed
            ({status} = await helpers.getCredentialStatus(
              {verifiableCredential}));
            status.should.equal(true);
          }
        });
      });
    });
  }
});

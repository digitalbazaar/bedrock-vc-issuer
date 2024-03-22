/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
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

describe('issue APIs - Reference ID `assertionMethod:foo` backwards ' +
  'compatibility test', () => {
  const zcaps = {};
  describe('Ed25519Signature2020', function() {
    let capabilityAgent;
    let noStatusListIssuerId;
    let noStatusListIssuerRootZcap;
    let sl2021RevocationIssuerConfig;
    let sl2021RevocationIssuerId;
    let sl2021RevocationRootZcap;
    let sl2021RevocationStatusId;
    let sl2021RevocationStatusRootZcap;
    let sl2021SuspensionIssuerConfig;
    let sl2021SuspensionIssuerId;
    let sl2021SuspensionRootZcap;
    let sl2021SuspensionStatusId;
    let sl2021SuspensionStatusRootZcap;
    let oauth2IssuerConfig;
    beforeEach(async () => {
      const suiteName = 'Ed25519Signature2020';
      const secret = '53ad64ce-8e1d-11ec-bb12-10bf48838a41';
      const handle = 'test';
      const depOptions = {
        suiteOptions: {
          suiteName, algorithm: 'Ed25519', statusOptions: {suiteName}
        }
      };
      capabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

      // create keystore for capability agent
      const keystoreAgent = await helpers.createKeystoreAgent(
        {capabilityAgent});
      // generate key for signing VCs (make it a did:key DID for simplicity)
      const assertionMethodKey = await keystoreAgent.generateKey({
        type: 'asymmetric',
        publicAliasTemplate: 'did:key:{publicKeyMultibase}#' +
          '{publicKeyMultibase}'
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
        {capabilityAgent, zcaps, suiteName: 'Ed25519Signature2020'});
      noStatusListIssuerId = noStatusListIssuerConfig.id;
      noStatusListIssuerRootZcap =
          `urn:zcap:root:${encodeURIComponent(noStatusListIssuerId)}`;

      // Intentionally change the referenceId of the assertion method zcap
      // in the database to be lowercase
      await helpers.updateConfig({
        configId: noStatusListIssuerId,
        referenceId: 'assertionMethod:ed25519'
      });
      // Check if assertion method zcap has been updated
      const {config} = await helpers.findConfig({
        configId: noStatusListIssuerId
      });
      should.exist(config);
      should.exist(config.zcaps['assertionMethod:ed25519']);

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
        sl2021RevocationIssuerConfig = issuerConfig;
        sl2021RevocationIssuerId = issuerConfig.id;
        sl2021RevocationRootZcap =
          `urn:zcap:root:${encodeURIComponent(issuerConfig.id)}`;
        sl2021RevocationStatusId = statusConfig.id;
        sl2021RevocationStatusRootZcap =
          `urn:zcap:root:${encodeURIComponent(statusConfig.id)}`;
        // Intentionally change the referenceId of the assertion method zcap
        // in the database to be lowercase
        await helpers.updateConfig({
          configId: sl2021RevocationIssuerId,
          referenceId: 'assertionMethod:ed25519'
        });
        // Check if assertion method zcap has been updated
        const {config} = await helpers.findConfig({
          configId: sl2021RevocationIssuerId
        });
        should.exist(config);
        should.exist(config.zcaps['assertionMethod:ed25519']);
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
        sl2021SuspensionIssuerConfig = issuerConfig;
        sl2021SuspensionIssuerId = issuerConfig.id;
        sl2021SuspensionRootZcap =
          `urn:zcap:root:${encodeURIComponent(issuerConfig.id)}`;
        sl2021SuspensionStatusId = statusConfig.id;
        sl2021SuspensionStatusRootZcap =
          `urn:zcap:root:${encodeURIComponent(statusConfig.id)}`;
        // Intentionally change the referenceId of the assertion method zcap
        // in the database to be uppercase
        await helpers.updateConfig({
          configId: sl2021SuspensionIssuerId,
          referenceId: 'assertionMethod:Ed25519'
        });
        // Check if assertion method zcap has been updated
        const {config} = await helpers.findConfig({
          configId: sl2021SuspensionIssuerId
        });
        should.exist(config);
        should.exist(config.zcaps['assertionMethod:Ed25519']);
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
    });

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
            const {statusListOptions: [{indexAllocator}]} =
              sl2021RevocationIssuerConfig;
            await zcapClient.write({
              url: `${sl2021RevocationStatusId}/credentials/status`,
              capability: sl2021RevocationStatusRootZcap,
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
            const {statusListOptions: [{indexAllocator}]} =
              sl2021SuspensionIssuerConfig;
            await zcapClient.write({
              url: `${sl2021SuspensionStatusId}/credentials/status`,
              capability: sl2021SuspensionStatusRootZcap,
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
            capability: sl2021SuspensionStatusRootZcap,
            json: {}
          });

          // check status of VC has changed
          ({status} = await helpers.getCredentialStatus(
            {verifiableCredential}));
          status.should.equal(true);
        });
    });
  });
});

/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {createRequire} from 'node:module';
import {klona} from 'klona';

const require = createRequire(import.meta.url);

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');

describe('issue APIs - Reference ID `assertionMethod:foo` backwards ' +
  'compatibility test', () => {
  describe('Ed25519Signature2020', function() {
    let capabilityAgent;
    let zcaps;
    let noStatusListIssuerId;
    let noStatusListIssuerRootZcap;
    let sl2021Revocation;
    let sl2021Suspension;
    beforeEach(async () => {
      const suiteName = 'Ed25519Signature2020';
      const depOptions = {
        suiteOptions: {
          suiteName, algorithm: 'Ed25519', statusOptions: {suiteName}
        }
      };

      // provision dependencies
      ({capabilityAgent, zcaps} = await helpers.provisionDependencies({
        status: false,
        cryptosuites: [{
          name: suiteName,
          algorithm: 'Ed25519'
        }],
        zcaps: true
      }));

      // create issuer instance w/ no status list options
      const noStatusListIssuerConfig = await helpers.createIssuerConfig(
        {capabilityAgent, zcaps, suiteName});
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
        const statusListOptions = [{
          type: 'StatusList2021',
          statusPurpose: 'revocation',
          zcapReferenceIds: {
            createCredentialStatusList: 'createCredentialStatusList'
          }
        }];
        sl2021Revocation = await helpers.createIssuerConfigAndDependencies({
          capabilityAgent, zcaps, suiteName, statusListOptions, depOptions
        });

        // Intentionally change the referenceId of the assertion method zcap
        // in the database to be lowercase
        await helpers.updateConfig({
          configId: sl2021Revocation.issuerId,
          referenceId: 'assertionMethod:ed25519'
        });
        // Check if assertion method zcap has been updated
        const {config} = await helpers.findConfig({
          configId: sl2021Revocation.issuerId
        });
        should.exist(config);
        should.exist(config.zcaps['assertionMethod:ed25519']);
      }

      // create issuer instance w/ status list 2021 status list options
      // w/ suspension status purpose
      {
        const statusListOptions = [{
          type: 'StatusList2021',
          statusPurpose: 'suspension',
          zcapReferenceIds: {
            createCredentialStatusList: 'createCredentialStatusList'
          }
        }];
        sl2021Suspension = await helpers.createIssuerConfigAndDependencies({
          capabilityAgent, zcaps, suiteName, statusListOptions, depOptions
        });

        // Intentionally change the referenceId of the assertion method zcap
        // in the database to be uppercase
        await helpers.updateConfig({
          configId: sl2021Suspension.issuerId,
          referenceId: 'assertionMethod:Ed25519'
        });
        // Check if assertion method zcap has been updated
        const {config} = await helpers.findConfig({
          configId: sl2021Suspension.issuerId
        });
        should.exist(config);
        should.exist(config.zcaps['assertionMethod:Ed25519']);
      }
    });
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
    it('issues a valid credential w/ SL 2021 "credentialStatus" and ' +
      'suspension status purpose', async () => {
      const credential = klona(mockCredential);
      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${sl2021Suspension.issuerId}/credentials/issue`,
          capability: sl2021Suspension.rootZcap,
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

    it('updates a StatusList2021 revocation credential status', async () => {
      // first issue VC
      const credential = klona(mockCredential);
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      const {data: {verifiableCredential}} = await zcapClient.write({
        url: `${sl2021Revocation.issuerId}/credentials/issue`,
        capability: sl2021Revocation.rootZcap,
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
          sl2021Revocation.issuerConfig;
        await zcapClient.write({
          url: `${sl2021Revocation.statusId}/credentials/status`,
          capability: sl2021Revocation.statusRootZcap,
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
        capability: sl2021Revocation.statusRootZcap,
        json: {}
      });

      // check status of VC has changed
      ({status} = await helpers.getCredentialStatus(
        {verifiableCredential}));
      status.should.equal(true);
    });
    it('updates a StatusList2021 suspension credential status', async () => {
      // first issue VC
      const credential = klona(mockCredential);
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      const {data: {verifiableCredential}} = await zcapClient.write({
        url: `${sl2021Suspension.issuerId}/credentials/issue`,
        capability: sl2021Suspension.rootZcap,
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
          sl2021Suspension.issuerConfig;
        await zcapClient.write({
          url: `${sl2021Suspension.statusId}/credentials/status`,
          capability: sl2021Suspension.statusRootZcap,
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
        capability: sl2021Suspension.statusRootZcap,
        json: {}
      });

      // check status of VC has changed
      ({status} = await helpers.getCredentialStatus(
        {verifiableCredential}));
      status.should.equal(true);
    });
  });
});

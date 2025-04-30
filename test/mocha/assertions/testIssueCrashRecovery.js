/*!
 * Copyright (c) 2020-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from '../helpers.js';
import {createRequire} from 'node:module';
import {issuer} from '@bedrock/vc-issuer';
import {mockData} from '../mock.data.js';
import sinon from 'sinon';
import {randomUUID as uuid} from 'node:crypto';

const require = createRequire(import.meta.url);

const {_CredentialStatusWriter} = issuer;

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('../mock-credential.json');
const mockTerseCredential = require('../mock-terse-credential.json');

export function testIssueCrashRecovery({
  suiteName, algorithm, issueOptions, statusOptions,
  terseIssueOptions = issueOptions
}) {
  const depOptions = {
    suiteOptions: {
      suiteName, algorithm, issueOptions, statusOptions, terseIssueOptions
    },
    cryptosuites: [{
      name: suiteName,
      algorithm
    }],
    zcaps: true
  };
  describe('issue crash recovery', function() {
    let capabilityAgent;
    let zcaps;
    let bslRevocation;
    let smallBsl;
    let smallTerseStatusList;
    before(async () => {
      // provision dependencies
      ({capabilityAgent, zcaps} = await helpers.provisionDependencies(
        depOptions));

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

    // stub modules in order to simulate failure conditions
    let credentialStatusWriterStub;
    let mathRandomStub;
    beforeEach(async () => {
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
    afterEach(async () => {
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
      const credential1 = structuredClone(mockCredential);
      credential1.id = 'urn:id1';
      const {data: {verifiableCredential: vc1}} = await zcapClient.write({
        url: `${bslRevocation.issuerId}/credentials/issue`,
        capability: bslRevocation.rootZcap,
        json: {credential: credential1, options: issueOptions}
      });

      const vc1StatusId = vc1.credentialStatus.id;

      // now issue second VC (should succeed and process the
      const credential2 = structuredClone(mockCredential);
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
      let credential = structuredClone(mockCredential);
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
      credential = structuredClone(mockCredential);
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
        const credential = structuredClone(mockCredential);
        delete credential.id;
        let error;
        let result;
        try {
          result = await zcapClient.write({
            url: `${bslRevocation.issuerId}/credentials/issue`,
            capability: bslRevocation.rootZcap,
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
        const credential = structuredClone(mockCredential);
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
        const credential = structuredClone(mockCredential);
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
        const credential = structuredClone(mockCredential);
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
        const credential = structuredClone(mockTerseCredential);
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
}

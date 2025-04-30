/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as assertions from './index.js';
import * as helpers from '../helpers.js';
import {createRequire} from 'node:module';
import {randomUUID as uuid} from 'node:crypto';

const require = createRequire(import.meta.url);

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('../mock-credential.json');

export function testBitstringStatusList({
  suiteName, algorithm, issueOptions, statusOptions
}) {
  describe('BitstringStatusList', function() {
    // all the status purpose combinations to test
    const statusPurposes = [
      'activation',
      'revocation',
      'suspension',
      ['activation', 'revocation', 'suspension']
    ];
    for(const statusPurpose of statusPurposes) {
      testStatusPurpose({
        suiteName, algorithm, issueOptions, statusOptions, statusPurpose
      });
    }
  });
}

function testStatusPurpose({
  suiteName, algorithm, issueOptions, statusOptions, statusPurpose
}) {
  const depOptions = {
    suiteOptions: {
      suiteName, algorithm, issueOptions, statusOptions
    },
    cryptosuites: [{
      name: suiteName,
      algorithm
    }],
    zcaps: true
  };
  describe(`BitstringStatusList, statusPurpose: ${statusPurpose}`, function() {
    let issuer;
    let capabilityAgent;
    let zcaps;
    let bslInstance;
    before(async () => {
      // provision dependencies
      ({issuer, capabilityAgent, zcaps} = await helpers.provisionDependencies(
        depOptions));

      // create issuer instance w/ bitstring status list options
      const statusListOptions = [{
        type: 'BitstringStatusList',
        statusPurpose,
        zcapReferenceIds: {
          createCredentialStatusList: 'createCredentialStatusList'
        }
      }];
      const {cryptosuites} = depOptions;
      const issueOptions = helpers.createIssueOptions({issuer, cryptosuites});
      bslInstance = await helpers.createIssuerConfigAndDependencies({
        capabilityAgent, zcaps, issueOptions, statusListOptions, depOptions
      });
    });
    describe('issue', () => {
      it('issues a valid credential w/ "credentialStatus"', async () => {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        const credential = structuredClone(mockCredential);
        credential.id = `urn:uuid:${uuid()}`;
        let error;
        let result;
        try {
          result = await zcapClient.write({
            url: `${bslInstance.issuerId}/credentials/issue`,
            capability: bslInstance.rootZcap,
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
        // not supported with old `Ed25519Signature2020`
        if(suiteName !== 'Ed25519Signature2020') {
          // `created` should not be set by default because new issue config
          // mechanism was used w/o requesting it
          should.not.exist(verifiableCredential.proof.created);
        }

        await assertions.assertStoredCredential({
          configId: bslInstance.issuerId,
          credentialId: verifiableCredential.id,
          zcapClient,
          capability: bslInstance.rootZcap,
          expectedCredential: verifiableCredential
        });
      });
      it('fails when trying to issue a duplicate credential', async () => {
        const zcapClient = helpers.createZcapClient({capabilityAgent});

        // issue VC (should succeed)
        const credentialId = `urn:uuid:${uuid()}`;
        let credential = structuredClone(mockCredential);
        credential.id = credentialId;
        let error;
        let result;
        try {
          result = await zcapClient.write({
            url: `${bslInstance.issuerId}/credentials/issue`,
            capability: bslInstance.rootZcap,
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
        credential.id = credentialId;
        result = undefined;
        try {
          result = await zcapClient.write({
            url: `${bslInstance.issuerId}/credentials/issue`,
            capability: bslInstance.rootZcap,
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
              url: `${bslInstance.issuerId}/credentials/issue`,
              capability: bslInstance.rootZcap,
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
              url: `${bslInstance.issuerId}/credentials/issue`,
              capability: bslInstance.rootZcap,
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
              url: `${bslInstance.issuerId}/credentials/issue`,
              capability: bslInstance.rootZcap,
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
    });
    describe('status', () => {
      let zcapClient;
      let verifiableCredential;
      before(async () => {
        // first issue VC
        const credential = structuredClone(mockCredential);
        credential.id = `urn:uuid:${uuid()}`;
        zcapClient = helpers.createZcapClient({capabilityAgent});
        ({data: {verifiableCredential}} = await zcapClient.write({
          url: `${bslInstance.issuerId}/credentials/issue`,
          capability: bslInstance.rootZcap,
          json: {credential, options: issueOptions}
        }));
      });
      const purposes = Array.isArray(statusPurpose) ?
        statusPurpose : [statusPurpose];
      for(const statusPurpose of purposes) {
        it(`updates "${statusPurpose}" credential status`, async () => {
          // get VC status
          let statusInfo = await helpers.getCredentialStatus(
            {verifiableCredential, statusPurpose});
          statusInfo.status.should.equal(false);
          statusInfo.credentialStatus.statusPurpose.should.equal(statusPurpose);

          // then set status
          let error;
          try {
            const {statusListOptions: [{indexAllocator}]} =
              bslInstance.issuerConfig;
            await zcapClient.write({
              url: `${bslInstance.statusId}/credentials/status`,
              capability: bslInstance.statusRootZcap,
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
            capability: bslInstance.statusRootZcap,
            json: {}
          });

          // check status of VC has changed
          statusInfo = await helpers.getCredentialStatus(
            {verifiableCredential, statusPurpose});
          statusInfo.status.should.equal(true);
          statusInfo.credentialStatus.statusPurpose.should.equal(statusPurpose);
        });
      }
    });
  });
}

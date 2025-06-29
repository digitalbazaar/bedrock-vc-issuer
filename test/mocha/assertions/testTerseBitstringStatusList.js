/*!
 * Copyright (c) 2020-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from '../helpers.js';
import {createRequire} from 'node:module';
import {mockData} from '../mock.data.js';
import {randomUUID as uuid} from 'node:crypto';

const require = createRequire(import.meta.url);

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockTerseCredential = require('../mock-terse-credential.json');

export function testTerseBitstringStatusList({
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
  describe('TerseBitstringStatusList', function() {
    let issuer;
    let capabilityAgent;
    let zcaps;
    let terseMultistatus;
    before(async () => {
      // provision dependencies
      ({issuer, capabilityAgent, zcaps} = await helpers.provisionDependencies(
        depOptions));

      // create issuer instance w/ terse bitstring status list options
      // w/ revocation AND suspension status purpose
      {
        const statusListOptions = [{
          type: 'TerseBitstringStatusList',
          statusPurpose: ['revocation', 'suspension'],
          zcapReferenceIds: {
            createCredentialStatusList: 'createCredentialStatusList'
          }
        }];
        const {cryptosuites} = depOptions;
        const issueOptions = helpers.createIssueOptions({issuer, cryptosuites});
        terseMultistatus = await helpers
          .createIssuerConfigAndDependencies({
            capabilityAgent, zcaps, issueOptions, statusListOptions, depOptions
          });

        // insert example context for issuing VCs w/terse status entries
        const {
          testBarcodeCredentialContextUrl,
          testBarcodeCredentialContext
        } = mockData;
        const client = helpers.createZcapClient({capabilityAgent});
        const url = `${terseMultistatus.issuerId}/contexts`;
        await client.write({
          url, json: {
            id: testBarcodeCredentialContextUrl,
            context: testBarcodeCredentialContext
          },
          capability: terseMultistatus.rootZcap
        });
      }
    });
    it('issues a valid credential w/ terse "credentialStatus" for ' +
      'both revocation and suspension status purpose', async () => {
      const credential = structuredClone(mockTerseCredential);
      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${terseMultistatus.issuerId}/credentials/issue`,
          capability: terseMultistatus.rootZcap,
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
      // not supported with old `Ed25519Signature2020`
      if(suiteName !== 'Ed25519Signature2020') {
        // `created` should not be set by default because new issue config
        // mechanism was used w/o requesting it
        should.not.exist(verifiableCredential.proof.created);
      }
    });

    it('updates multiple TerseBitstringStatusList statuses', async () => {
      // first issue VC
      const credential = structuredClone(mockTerseCredential);
      const credentialId = `urn:uuid:${uuid()}`;
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      const {data: {verifiableCredential}} = await zcapClient.write({
        url: `${terseMultistatus.issuerId}/credentials/issue`,
        capability: terseMultistatus.rootZcap,
        json: {
          credential,
          options: {...terseIssueOptions, credentialId}
        }
      });

      // get VC statuses
      const listLength = 67108864;
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
            terseMultistatus.issuerConfig;
          await zcapClient.write({
            url: `${terseMultistatus.statusId}/credentials/status`,
            capability: terseMultistatus.statusRootZcap,
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
            terseMultistatus.issuerConfig;
          await zcapClient.write({
            url: `${terseMultistatus.statusId}/credentials/status`,
            capability: terseMultistatus.statusRootZcap,
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
        capability: terseMultistatus.statusRootZcap,
        json: {}
      });
      await zcapClient.write({
        url: `${suspensionStatusInfo.statusListCredential}?refresh=true`,
        capability: terseMultistatus.statusRootZcap,
        json: {}
      });

      // check statuses of VC have changed
      const newRevocationStatus = await helpers.getCredentialStatus(
        {verifiableCredential, statusPurpose: 'revocation', listLength});
      newRevocationStatus.status.should.equal(true);
      const newSuspensionStatus = await helpers.getCredentialStatus(
        {verifiableCredential, statusPurpose: 'suspension', listLength});
      newSuspensionStatus.status.should.equal(true);
    });
  });
}

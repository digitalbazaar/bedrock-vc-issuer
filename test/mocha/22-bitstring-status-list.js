/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as assertions from './assertions.js';
import * as helpers from './helpers.js';
import {createRequire} from 'node:module';
import {klona} from 'klona';
import {v4 as uuid} from 'uuid';

const require = createRequire(import.meta.url);

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');

describe('issue with BitstringStatusList', () => {
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
    },
    'bbs-2023': {
      algorithm: ['Bls12381G2'],
      statusOptions: {
        // sign status list with simple ECDSA
        algorithm: 'P-256',
        suiteName: 'ecdsa-rdfc-2019'
      }
    }
  };
  for(const suiteName in suiteNames) {
    const suiteInfo = suiteNames[suiteName];
    const {issueOptions, statusOptions} = suiteInfo;
    const algorithms = Array.isArray(suiteInfo.algorithm) ?
      suiteInfo.algorithm : [suiteInfo.algorithm];
    for(const algorithm of algorithms) {
      describeSuite({
        suiteName, algorithm, issueOptions, statusOptions
      });
    }
  }
  function describeSuite({
    suiteName, algorithm, issueOptions, statusOptions
  }) {
    const testDescription = `${suiteName}, algorithm: ${algorithm}`;
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
    describe(testDescription, function() {
      let capabilityAgent;
      let zcaps;
      // FIXME: convert to loop based on params
      let bslRevocation;
      let bslSuspension;
      let bslRevocationSuspension;
      beforeEach(async () => {
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

        // create issuer instance w/ bitstring status list status list options
        // w/ suspension status purpose
        {
          const statusListOptions = [{
            type: 'BitstringStatusList',
            statusPurpose: 'suspension',
            zcapReferenceIds: {
              createCredentialStatusList: 'createCredentialStatusList'
            }
          }];
          bslSuspension = await helpers.createIssuerConfigAndDependencies({
            capabilityAgent, zcaps, suiteName, statusListOptions, depOptions
          });
        }

        // create issuer instance w/ bitstring status list options
        // w/ both revocation and suspension status purposes
        {
          const statusListOptions = [{
            type: 'BitstringStatusList',
            statusPurpose: ['revocation', 'suspension'],
            zcapReferenceIds: {
              createCredentialStatusList: 'createCredentialStatusList'
            }
          }];
          bslRevocationSuspension = await helpers
            .createIssuerConfigAndDependencies({
              capabilityAgent, zcaps, suiteName, statusListOptions, depOptions
            });
        }
      });
      describe('/credentials/issue', () => {
        it('issues a valid credential w/ "credentialStatus" and ' +
          'suspension status purpose', async () => {
          const zcapClient = helpers.createZcapClient({capabilityAgent});
          const credential = klona(mockCredential);
          let error;
          let result;
          try {
            result = await zcapClient.write({
              url: `${bslSuspension.issuerId}/credentials/issue`,
              capability: bslSuspension.rootZcap,
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

          await assertions.assertStoredCredential({
            configId: bslSuspension.issuerId,
            credentialId: verifiableCredential.id,
            zcapClient,
            capability: bslSuspension.rootZcap,
            expectedCredential: verifiableCredential
          });
        });
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
      });

      describe('/credentials/status', () => {
        it('updates a BitstringStatusList revocation credential status',
          async () => {
            // first issue VC
            const credential = klona(mockCredential);
            const zcapClient = helpers.createZcapClient({capabilityAgent});
            const {data: {verifiableCredential}} = await zcapClient.write({
              url: `${bslRevocation.issuerId}/credentials/issue`,
              capability: bslRevocation.rootZcap,
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
                bslRevocation.issuerConfig;
              await zcapClient.write({
                url: `${bslRevocation.statusId}/credentials/status`,
                capability: bslRevocation.statusRootZcap,
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
              capability: bslRevocation.statusRootZcap,
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
              url: `${bslSuspension.issuerId}/credentials/issue`,
              capability: bslSuspension.rootZcap,
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
                bslSuspension.issuerConfig;
              await zcapClient.write({
                url: `${bslSuspension.statusId}/credentials/status`,
                capability: bslSuspension.statusRootZcap,
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
              capability: bslSuspension.statusRootZcap,
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
              url: `${bslRevocationSuspension.issuerId}/credentials/issue`,
              capability: bslRevocationSuspension.rootZcap,
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
                  bslRevocationSuspension.issuerConfig;
                await zcapClient.write({
                  url: `${bslRevocationSuspension.statusId}/credentials/status`,
                  capability: bslRevocationSuspension.statusRootZcap,
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
                capability: bslRevocationSuspension.statusRootZcap,
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
                  bslRevocationSuspension.issuerConfig;
                await zcapClient.write({
                  url: `${bslRevocationSuspension.statusId}/credentials/status`,
                  capability: bslRevocationSuspension.statusRootZcap,
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
                capability: bslRevocationSuspension.statusRootZcap,
                json: {}
              });

              // check status of VC has changed
              ({status} = await helpers.getCredentialStatus(
                {verifiableCredential, statusPurpose: 'revocation'}));
              status.should.equal(true);
            }
          });
      });
    });
  }
});

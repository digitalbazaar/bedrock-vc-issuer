/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {createRequire} from 'node:module';
import {httpClient} from '@digitalbazaar/http-client';
import {klona} from 'klona';
import {mockData} from './mock.data.js';
import {v4 as uuid} from 'uuid';

const require = createRequire(import.meta.url);

const {baseUrl} = mockData;
const serviceType = 'vc-issuer';

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');

describe.skip('issue using VC-JWT format w/status list support', () => {
  let capabilityAgent;
  let keystoreAgent;
  let issuerCreateStatusListZcap;
  let issuerConfig;
  let issuerId;
  let issuerRootZcap;
  let statusConfig;
  let statusId;
  let statusRootZcap;
  beforeEach(async () => {
    // use envelope-based security
    const envelope = {
      format: 'VC-JWT',
      algorithm: 'P-256'
    };

    // generate a `did:web` DID for the issuer
    const {host} = bedrock.config.server;
    const localId = uuid();
    const did = `did:web:${encodeURIComponent(host)}:did-web:${localId}`;

    // provision dependencies
    ({
      capabilityAgent, keystoreAgent,
      statusConfig, issuerCreateStatusListZcap
    } = await helpers.provisionDependencies({
      did, envelope, suiteOptions: {
        statusOptions: {
          envelope
        }
      }
    }));

    // create EDV for storage (creating hmac and kak in the process)
    const {
      edvConfig,
      hmac,
      keyAgreementKey
    } = await helpers.createEdv({capabilityAgent, keystoreAgent});

    // get service agent to delegate to
    const serviceAgentUrl =
      `${baseUrl}/service-agents/${encodeURIComponent(serviceType)}`;
    const {data: serviceAgent} = await httpClient.get(serviceAgentUrl, {agent});

    // delegate edv, hmac, and key agreement key zcaps to service agent
    const zcaps = await helpers.delegateEdvZcaps({
      edvConfig, hmac, keyAgreementKey, serviceAgent,
      capabilityAgent
    });

    // delegate assertion method keys
    await helpers.delegateAssertionMethodZcaps({
      envelope, serviceAgent, capabilityAgent, zcaps
    });

    // create issue options
    const issueOptions = {
      issuer: did,
      envelope: {
        format: envelope.format,
        zcapReferenceIds: envelope.zcapReferenceIds
      }
    };

    // create `did:web` DID document for issuer
    const didDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
        'https://w3id.org/security/multikey/v1'
      ],
      id: did,
      verificationMethod: [],
      assertionMethod: []
    };
    for(const {assertionMethodKey} of [envelope]) {
      const description = await assertionMethodKey.getKeyDescription();
      delete description['@context'];
      didDocument.verificationMethod.push(description);
      didDocument.assertionMethod.push(description.id);
    }
    // add DID doc to map with DID docs to be served
    mockData.didWebDocuments.set(localId, didDocument);

    // create issuer instance w/ bitstring status list options
    // w/ revocation status purpose
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
    ({issuerConfig} = await helpers.createIssuerConfig({
      capabilityAgent, zcaps: newZcaps, statusListOptions, issueOptions
    }));
    issuerId = issuerConfig.id;
    issuerRootZcap = `urn:zcap:root:${encodeURIComponent(issuerId)}`;
    statusId = statusConfig.id;
    statusRootZcap = `urn:zcap:root:${encodeURIComponent(statusConfig.id)}`;
  });
  describe('/credentials/issue', () => {
    it('issues a VC-JWT VC 1.1 credential', async () => {
      const credential = klona(mockCredential);
      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${issuerId}/credentials/issue`,
          capability: issuerRootZcap,
          json: {
            credential,
            options: {
              extraInformation: 'abc'
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
      verifiableCredential.type.should.equal('EnvelopedVerifiableCredential');
      // FIXME: verify JWT-formatted envelope
      // FIXME: decode and verify credential status is present
      // should.exist(verifiableCredential.credentialSubject);
      // verifiableCredential.credentialSubject.should.be.an('object');
      // should.exist(verifiableCredential.credentialStatus);
    });
  });
  describe('/credentials/status', () => {
    it('updates a BitstringStatusList revocation credential status',
      async () => {
        // first issue VC
        const credential = klona(mockCredential);
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        const {data: {verifiableCredential}} = await zcapClient.write({
          url: `${issuerId}/credentials/issue`,
          capability: issuerRootZcap,
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
          const {statusListOptions: [{indexAllocator}]} = issuerConfig;
          await zcapClient.write({
            url: `${statusId}/credentials/status`,
            capability: statusRootZcap,
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
          capability: statusRootZcap,
          json: {}
        });

        // check status of VC has changed
        ({status} = await helpers.getCredentialStatus(
          {verifiableCredential}));
        status.should.equal(true);

        // FIXME: check returned status VC envelope and ensure it is
        // JWT-encoded
      });
  });
});

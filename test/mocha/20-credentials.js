/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {agent} = require('bedrock-https-agent');
const bedrock = require('bedrock');
const {CapabilityAgent} = require('@digitalbazaar/webkms-client');
const helpers = require('./helpers');
const {httpClient} = require('@digitalbazaar/http-client');
const mockData = require('./mock.data');
const {util: {clone}} = bedrock;

const {baseUrl} = mockData;
const serviceType = 'vc-issuer';

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential');

describe('issue APIs', () => {
  let capabilityAgent;
  let noStatusListIssuerId;
  let noStatusListIssuerRootZcap;
  let issuerId;
  let rootZcap;
  const zcaps = {};
  beforeEach(async () => {
    const secret = '53ad64ce-8e1d-11ec-bb12-10bf48838a41';
    const handle = 'test';
    capabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

    // create keystore for capability agent
    const keystoreAgent = await helpers.createKeystoreAgent(
      {capabilityAgent});

    // generate key for signing VCs (make it a did:key DID for simplicity)
    const assertionMethodKey = await keystoreAgent.generateKey({
      type: 'asymmetric',
      publicAliasTemplate: 'did:key:{publicKeyMultibase}#{publicKeyMultibase}'
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
    const {data: serviceAgent} = await httpClient.get(serviceAgentUrl, {
      agent
    });

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
    zcaps['assertionMethod:ed25519'] = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: assertionMethodKey.kmsId,
      delegator: capabilityAgent
    });

    // FIXME: include `statusListOptions` or create a second issuer with it

    // create issuer instance w/ no status list options
    const noStatusListIssuerConfig = await helpers.createConfig(
      {capabilityAgent, zcaps});
    noStatusListIssuerId = noStatusListIssuerConfig.id;
    noStatusListIssuerRootZcap =
      `urn:zcap:root:${encodeURIComponent(noStatusListIssuerId)}`;

    // create issuer instance w/ no status list options
    const statusListOptions = [{
      statusType: 'revoked',
      suiteName: 'Ed25519Signature2020'
    }];
    const issuerConfig = await helpers.createConfig(
      {capabilityAgent, zcaps, statusListOptions});
    issuerId = issuerConfig.id;
    rootZcap = `urn:zcap:root:${encodeURIComponent(issuerId)}`;
  });
  describe.only('/credentials/issue', () => {
    it('issues a valid credential w/no "credentialStatus"', async () => {
      const credential = clone(mockCredential);
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
      const {proof} = verifiableCredential;
      should.exist(proof);
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
    it('issues a valid credential w/ "credentialStatus"', async () => {
      const credential = clone(mockCredential);
      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${issuerId}/credentials/issue`,
          capability: rootZcap,
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
      const {proof} = verifiableCredential;
      should.exist(proof);
    });
  });

  describe.skip('/credentials/status', () => {
    it('updates a credential status', async () => {
      // FIXME: first issue VC

      // FIXME: then revoke VC
    });
  });
});

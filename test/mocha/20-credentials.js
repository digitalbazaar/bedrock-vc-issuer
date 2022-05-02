/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {createRequire} from 'module';
import {httpClient} from '@digitalbazaar/http-client';
import {issuer} from '@bedrock/vc-issuer';
import {klona} from 'klona';
import {mockData} from './mock.data.js';
import sinon from 'sinon';
const require = createRequire(import.meta.url);
const {CapabilityAgent} = require('@digitalbazaar/webkms-client');

const {_CredentialStatusWriter} = issuer;

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
    zcaps['assertionMethod:ed25519'] = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: assertionMethodKey.kmsId,
      delegator: capabilityAgent
    });

    // create issuer instance w/ no status list options
    const noStatusListIssuerConfig = await helpers.createConfig(
      {capabilityAgent, zcaps});
    noStatusListIssuerId = noStatusListIssuerConfig.id;
    noStatusListIssuerRootZcap =
      `urn:zcap:root:${encodeURIComponent(noStatusListIssuerId)}`;

    // create issuer instance w/ status list options
    const statusListOptions = [{
      type: 'RevocationList2020',
      statusPurpose: 'revocation',
      suiteName: 'Ed25519Signature2020'
    }];
    const issuerConfig = await helpers.createConfig(
      {capabilityAgent, zcaps, statusListOptions});
    issuerId = issuerConfig.id;
    rootZcap = `urn:zcap:root:${encodeURIComponent(issuerId)}`;
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
    it('issues a valid credential w/ "credentialStatus"', async () => {
      const credential = klona(mockCredential);
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
          url: `${issuerId}/credentials/issue`,
          capability: rootZcap,
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
          url: `${issuerId}/credentials/issue`,
          capability: rootZcap,
          json: {credential}
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      error.data.type.should.equal('DuplicateError');
    });
  });

  describe('/credentials/status', () => {
    it('updates a credential status', async () => {
      // first issue VC
      const credential = klona(mockCredential);
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      const {data: {verifiableCredential}} = await zcapClient.write({
        url: `${issuerId}/credentials/issue`,
        capability: rootZcap,
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
          url: `${issuerId}/credentials/status`,
          capability: rootZcap,
          json: {
            credentialId: verifiableCredential.id,
            credentialStatus: {
              type: 'RevocationList2020Status'
            }
          }
        });
      } catch(e) {
        error = e;
      }
      assertNoError(error);

      // force publication of new SLC
      await zcapClient.write({
        url: `${statusInfo.statusListCredential}/publish`,
        capability: rootZcap,
        json: {}
      });

      // check status of VC has changed
      ({status} = await helpers.getCredentialStatus({verifiableCredential}));
      status.should.equal(true);
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
        _CredentialStatusWriter.prototype, 'finish').callsFake(async () => {});
    });
    after(async () => {
      mathRandomStub.restore();
      credentialStatusWriterStub.restore();
    });

    it('successfully recovers from a simulated crash', async () => {
      const zcapClient = helpers.createZcapClient({capabilityAgent});

      // first issue a VC that is partially completed enough to return the
      // VC, however, the status list index bookkeeping is not updated
      // The earlier failure is detected by the second issue of a VC and
      // the bookkeeping is repaired
      const credential1 = klona(mockCredential);
      credential1.id = 'urn:id1';
      const {data: {verifiableCredential: vc1}} = await zcapClient.write({
        url: `${issuerId}/credentials/issue`,
        capability: rootZcap,
        json: {credential: credential1}
      });

      const vc1StatusId = vc1.credentialStatus.id;

      // now issue second VC (should succeed and process the
      const credential2 = klona(mockCredential);
      credential2.id = 'urn:id2';
      const {data: {verifiableCredential: vc2}} = await zcapClient.write({
        url: `${issuerId}/credentials/issue`,
        capability: rootZcap,
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
    // ensure duplicate VCs are still properly detected when bookkeeping fails
    it('fails when trying to issue a duplicate credential', async () => {
      const zcapClient = helpers.createZcapClient({capabilityAgent});

      // issue VC (should succeed)
      let credential = klona(mockCredential);
      let error;
      let result;
      try {
        result = await zcapClient.write({
          url: `${issuerId}/credentials/issue`,
          capability: rootZcap,
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
          url: `${issuerId}/credentials/issue`,
          capability: rootZcap,
          json: {credential}
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      error.data.type.should.equal('DuplicateError');
    });
  });
});

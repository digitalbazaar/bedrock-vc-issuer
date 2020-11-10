/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config, util: {delay, clone}} = require('bedrock');
const {create} = require('apisauce');
const {httpsAgent} = require('bedrock-https-agent');
const helpers = require('./helpers.js');
const sinon = require('sinon');
const brPassport = require('bedrock-passport');
const mockData = require('./mockData.json');

const api = create({
  baseURL: `${config.server.baseUri}/vc-issuer`,
  httpsAgent,
  timeout: 10000,
});
const privateKmsBaseUrl = `${config.server.baseUri}/kms`;
const publicKmsBaseUrl = `${config.server.baseUri}/kms`;

describe('API', function() {

  describe('issue POST endpoint', function() {
    let agents;
    before(async function() {
      const accountId = 'urn:uuid:e9b57b37-2fea-43d6-82cb-f4a02c144e38';
      const didMethod = 'key';
      agents = await helpers.insertIssuerAgent({
        privateKmsBaseUrl,
        publicKmsBaseUrl,
        didMethod,
        id: accountId,
        token: 'test-token-9b57b37-2fea-43d6-82cb-f4a02c144e38'
      });
    });
    after(async function() {
      // this is necessary due to mocha throwing
      // on uncaught exceptions due to a lingering fire and forget
      // promise made in CredentialStatusWriter
      // FIXME remove this once we implement a better bedrock shutdown
      // method: https://github.com/digitalbazaar/bedrock/issues/60
      await delay(2000);
    });
    it('should issue a credential', async function() {
      const {integration: {secrets}} = agents;
      const credential = clone(mockData.credential);
      const {token} = secrets;
      const result = await api.post(
        '/issue',
        {credential},
        {headers: {Authorization: `Bearer ${token}`}}
      );
      result.status.should.equal(200);
      should.exist(result.data);
      result.data.should.be.an('object');
      should.exist(result.data.verifiableCredential);
      const {verifiableCredential} = result.data;
      verifiableCredential.should.be.an('object');
      should.exist(verifiableCredential['@context']);
      should.exist(verifiableCredential.id);
      should.exist(verifiableCredential.type);
      should.exist(verifiableCredential.issuer);
      should.exist(verifiableCredential.issuanceDate);
      should.exist(verifiableCredential.expirationDate);
      should.exist(verifiableCredential.credentialSubject);
      verifiableCredential.credentialSubject.should.be.an('object');
      should.exist(verifiableCredential.credentialStatus);
      should.exist(verifiableCredential.proof);
      verifiableCredential.proof.should.be.an('object');
    });
    it('should not issue a duplicate credential', async function() {
      const {integration: {secrets}} = agents;
      const credential = clone(mockData.credential);
      credential.id = 'did:test:duplicate';
      credential.credentialSubject.id = 'did:test:duplicate';
      const {token} = secrets;
      // the first issue request should succeed
      const result = await api.post(
        '/issue',
        {credential},
        {headers: {Authorization: `Bearer ${token}`}}
      );
      result.status.should.equal(200);
      should.exist(result.data);
      result.data.should.be.an('object');
      should.exist(result.data.verifiableCredential);
      // the duplicate request should result in an error
      const duplicateResult = await api.post(
        '/issue',
        {credential},
        {headers: {Authorization: `Bearer ${token}`}}
      );
      duplicateResult.status.should.equal(409);
      const {data} = duplicateResult;
      should.exist(data);
      data.should.have.property('message');
      data.message.should.contain(
        'Could not issue credential; duplicate credential ID.');
      data.should.have.property('type');
      data.type.should.contain('DuplicateError');
    });

  });

  describe('authenticate POST endpoint', function() {
    let presentation = null;
    beforeEach(function() {
      presentation = clone(mockData.authPresentation);
    });
    it('should authenticate without an existing account', async function() {
      const result = await api.post('/authenticate', {presentation});
      should.exist(result);
      result.status.should.equal(200);
      result.data.should.be.an('object');
      result.data.should.have.property('id');
      result.data.id.should.be.a('string');
      // accounts created by this method should not have an email
      result.data.should.not.have.property('email');
      result.data.should.have.property('controller');
      result.data.controller.should.be.a('string');
      result.data.controller.should.contain(presentation.holder);
      result.data.should.have.property('capabilityAgentSeed');
      result.data.capabilityAgentSeed.should.be.a('string');
    });
    it('should authenticate with an existing account', async function() {
      const {account} = mockData.accounts.authenticate;
      await helpers.insertAccount({account});
      const withController = {
        ...presentation,
        holder: account.controller
      };
      const result = await api.post(
        '/authenticate', {presentation: withController});
      should.exist(result);
      result.status.should.equal(200);
      result.data.should.be.an('object');
      result.data.should.have.property('id');
      result.data.id.should.be.a('string');
      // existing accounts should return properties in the account object
      result.data.should.have.property('email');
      result.data.email.should.be.a('string');
      result.data.should.have.property('controller');
      result.data.controller.should.be.a('string');
      result.data.should.have.property('capabilityAgentSeed');
      result.data.capabilityAgentSeed.should.be.a('string');
      result.data.should.eql(account);
    });
    it('should not authenticate without a holder', async function() {
      delete presentation.holder;
      const result = await api.post('/authenticate', {presentation});
      should.exist(result);
      helpers.shouldBeAValidationError(result);
    });
    it('should not authenticate without a proof', async function() {
      delete presentation.proof;
      const result = await api.post('/authenticate', {presentation});
      should.exist(result);
      helpers.shouldBeAValidationError(result);
    });
    it('should not authenticate without a verificationMethod',
      async function() {
        delete presentation.proof.verificationMethod;
        const result = await api.post('/authenticate', {presentation});
        should.exist(result);
        helpers.shouldBeAValidationError(result);
      });
    it('should not authenticate if the purpose is not authentication',
      async function() {
        presentation.proof.proofPurpose = 'test-failure';
        const result = await api.post('/authenticate', {presentation});
        should.exist(result);
        helpers.shouldBeAValidationError(result);
      });
  }); // end authenticate POST

  describe.skip('rlc POST endpoint', function() {
    describe('authenticated', function() {
      let agents;
      let passportStub;
      const accountId = 'urn:uuid:c9b57b37-2fea-43d6-82cb-f4a02c144e39';
      const didMethod = 'v1';
      before(async function() {
        agents = await helpers.insertIssuerAgent({
          id: accountId,
          didMethod,
          token: 'test-token-8b57b37-2fea-43d6-82cb-f4a02c144e22'
        });
        passportStub = sinon.stub(brPassport, 'optionallyAuthenticated');
        helpers.stubPassport({passportStub, account: {id: accountId}});
      });
      after(async function() {
        passportStub.restore();
        // this is necessary due to mocha throwing
        // on uncaught exceptions due to a lingering fire and forget
        // promise made in CredentialStatusWriter
        // FIXME remove this once we implement a better bedrock shutdown
        // method: https://github.com/digitalbazaar/bedrock/issues/60
        await delay(2000);
      });
      it('should publish revocation list', async function() {
        const {integration} = agents;
        const {secrets, profileAgent} = integration;
        const instanceId = profileAgent.id;
        const rlcId = 'bar';
        const {token} = secrets;
        const result = await api.post(
          `/instances/${instanceId}/rlc/${rlcId}/publish`,
          {profileAgent: instanceId},
          {headers: {Authorization: `Bearer ${token}`}}
        );
        result.status.should.equal(200);
      });
    }); // end authenticated
  }); // end rlc POST

  describe('rlc GET endpoint', () => {
  }); // end rlc GET

});

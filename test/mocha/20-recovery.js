/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config, util: {clone}} = require('bedrock');
const {create} = require('apisauce');
const {httpsAgent} = require('bedrock-https-agent');
const helpers = require('./helpers.js');
const sinon = require('sinon');
const {_CredentialStatusWriter} = require('bedrock-vc-issuer');
const mockData = require('./mockData.json');

const api = create({
  baseURL: `${config.server.baseUri}/vc-issuer`,
  httpsAgent,
  timeout: 10000,
});
const privateKmsBaseUrl = `${config.server.baseUri}/kms`;
const publicKmsBaseUrl = `${config.server.baseUri}/kms`;

describe('Failure recovery', function() {
  let agents;
  let agent2;
  before(async function() {
    const accountId = 'urn:uuid:43f47a1f-acaf-4dd1-8597-001a8b0637e3';
    agents = await helpers.insertIssuerAgent({
      id: accountId,
      token: 'token-43f47a1f-acaf-4dd1-8597-001a8b0637e3',
      didMethod: 'key',
      publicKmsBaseUrl,
      privateKmsBaseUrl
    });
    agent2 = await helpers.insertIssuerAgent({
      id: accountId,
      token: 'token-43f47a1f-acaf-4dd1-8597-001a8b0637e4',
      didMethod: 'v1',
      publicKmsBaseUrl,
      privateKmsBaseUrl
    });
  });

  // stub modules in order to simulate failure conditions
  let credentialStatusWriterStub;
  let mathRandomStub;
  before(async () => {
    // Math.random will always return 0
    // this will ensure that the same shard is selected every time
    // see _chooseRandom helper in ListManager.js
    mathRandomStub = sinon.stub(Math, 'random').callsFake(() => 0);
    // credentiaStatuslWriter.finish is a noop
    // making this a noop is simulating a failure where the revocation list
    // bookkeeping was not completed after an issuance
    credentialStatusWriterStub = sinon.stub(
      _CredentialStatusWriter.prototype, 'finish').callsFake(async () => {});
  });
  after(async () => {
    mathRandomStub.restore();
    credentialStatusWriterStub.restore();
  });

  // first issue a VC that is partially completed enough to return the
  // VC, however, the revocation list index bookkeeping is not updated
  // The earlier failure is detected by the second issue of a VC and
  // the bookkeping is repaired
  it('should handle a crashed/partial issuance', async () => {
    const {integration: {secrets}} = agents;
    let credential = clone(mockData.credential);
    credential.id = 'urn:someId1';

    const {token} = secrets;
    const result1 = await api.post(
      '/issue',
      {credential},
      {headers: {Authorization: `Bearer ${token}`}}
    );
    const result1CredentialStatusId = result1.data.verifiableCredential
      .credentialStatus.id;

    credential = clone(mockData.credential);
    credential.id = 'urn:someId2';
    const result2 = await api.post(
      '/issue',
      {credential},
      {headers: {Authorization: `Bearer ${token}`}}
    );
    result2.status.should.equal(200);
    should.exist(result2.data);
    result2.data.should.be.an('object');
    should.exist(result2.data.verifiableCredential);
    const {verifiableCredential} = result2.data;
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
    const result2CredentialStatusId = result2.data.verifiableCredential
      .credentialStatus.id;

    // this test ensures that the two credentials are not issued with the same
    // revocation list index / hash fragment
    result2CredentialStatusId.should.not.equal(result1CredentialStatusId);
    const result1Hash = parseInt(result1CredentialStatusId.split('#')[1]);
    const result2Hash = parseInt(result2CredentialStatusId.split('#')[1]);
    result2Hash.should.equal(result1Hash + 1);
  });

  it('should handle a crashed/partial issuance using agent2 ' +
    'created using didMethod v1', async () => {
    const {integration: {secrets}} = agent2;
    let credential = clone(mockData.credential);
    credential.id = 'urn:someId1';

    const {token} = secrets;
    const result1 = await api.post(
      '/issue',
      {credential},
      {headers: {Authorization: `Bearer ${token}`}}
    );
    const result1CredentialStatusId = result1.data.verifiableCredential
      .credentialStatus.id;

    credential = clone(mockData.credential);
    credential.id = 'urn:someId2';
    const result2 = await api.post(
      '/issue',
      {credential},
      {headers: {Authorization: `Bearer ${token}`}}
    );
    console.log(result2.data);
    result2.status.should.equal(200);
    should.exist(result2.data);
    result2.data.should.be.an('object');
    should.exist(result2.data.verifiableCredential);
    const {verifiableCredential} = result2.data;
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
    const result2CredentialStatusId = result2.data.verifiableCredential
      .credentialStatus.id;

    // this test ensures that the two credentials are not issued with the same
    // revocation list index / hash fragment
    result2CredentialStatusId.should.not.equal(result1CredentialStatusId);
    const result1Hash = parseInt(result1CredentialStatusId.split('#')[1]);
    const result2Hash = parseInt(result2CredentialStatusId.split('#')[1]);
    result2Hash.should.equal(result1Hash + 1);
  });

  it('should error if duplicate credential id is posted', async () => {
    const {integration: {secrets}} = agents;
    const credential = clone(mockData.credential);
    credential.id = 'urn:someId3';
    const {token} = secrets;

    const result1 = await api.post(
      '/issue',
      {credential},
      {headers: {Authorization: `Bearer ${token}`}}
    );
    result1.status.should.equal(200);
    should.exist(result1.data);
    result1.data.should.be.an('object');
    should.exist(result1.data.verifiableCredential);
    // expect a duplicate error when the same credential is posted a second time
    const result2 = await api.post(
      '/issue',
      {credential},
      {headers: {Authorization: `Bearer ${token}`}}
    );
    result2.status.should.equal(409);
    should.exist(result2.data);
    result2.data.should.be.an('object');
    result2.data.message.should.equal('Could not issue credential; duplicate ' +
    'credential ID.');
    result2.data.type.should.equal('DuplicateError');
    should.not.exist(result2.data.verifiableCredential);
  });
});

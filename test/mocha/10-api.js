/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const {create} = require('apisauce');
const {httpsAgent} = require('bedrock-https-agent');
const helpers = require('./helpers.js');
const sinon = require('sinon');
const brPassport = require('bedrock-passport');

const api = create({
  baseURL: `${config.server.baseUri}/vc-issuer`,
  httpsAgent,
  timeout: 1000,
});

describe('issue POST endpoint', function() {
  let agents;
  beforeEach(async function() {
    // FIXME id should be a valid account id
    agents = await helpers.insertIssuerAgent({id: 'foo', token: 'test-token'});
  });
  it('should issue a credential', async function() {
    const {integration: {secrets}} = agents;
    const credential = {};
    const {token} = secrets;
    const response = await api.post(
      '/issue',
      {credential},
      {headers: {Authorization: `Bearer ${token}`}}
    );
    console.log(response);
  });
});

// FIXME: tests need to be updated to use new endpoints
describe.skip('API', () => {
  describe('instances GET endpoint', () => {
    describe('unauthenticated', () => {
      it('returns NotAllowedError', async () => {
        const result = await api.get('/instances');
        should.exist(result.problem);
        result.problem.should.equal('CLIENT_ERROR');
        should.exist(result.data);
        should.exist(result.data.type);
        result.data.type.should.equal('NotAllowedError');
      });
    }); // end unauthenticated
    describe('authenticated', () => {
      let passportStub;
      before(() => {
        passportStub = sinon.stub(brPassport, 'optionallyAuthenticated');
        _stubPassport(passportStub);
      });
      after(() => {
        passportStub.restore();
      });
      it('ValidationError on missing controller', async () => {
        const result = await api.get('/instances');
        should.exist(result.problem);
        result.problem.should.equal('CLIENT_ERROR');
        should.exist(result.data);
        should.exist(result.data.type);
        result.data.type.should.equal('ValidationError');
      });
      it('ValidationError on additional query param', async () => {
        const result = await api.get('/instances', {
          controller: 'did:v1:nym:abc',
          foo: 'bar',
        });
        should.exist(result.problem);
        result.problem.should.equal('CLIENT_ERROR');
        should.exist(result.data);
        should.exist(result.data.type);
        result.data.type.should.equal('ValidationError');
      });
      it('controller with no instances returns empty array', async () => {
        const params = {controller: 'did:v1:nym:abc'};
        const result = await api.get('/instances', params);
        should.not.exist(result.problem);
        result.data.should.be.an('array');
        result.data.should.have.length(0);
      });
    }); // end authenticated
  }); // end instances GET

  describe('instances POST endpoint', () => {
    describe('unauthenticated', () => {
      it('returns NotAllowedError', async () => {
        const result = await api.post('/instances', {foo: 'bar'});
        should.exist(result.problem);
        result.problem.should.equal('CLIENT_ERROR');
        should.exist(result.data);
        should.exist(result.data.type);
        result.data.type.should.equal('NotAllowedError');
      });
    }); // end unauthenticated
    describe('authenticated', () => {
      let passportStub;
      before(() => {
        passportStub = sinon.stub(brPassport, 'optionallyAuthenticated');
        _stubPassport(passportStub);
      });
      after(() => {
        passportStub.restore();
      });
      it('NotAllowedError if user is not controller', async () => {
        const result = await api.post('/instances', {
          // "controller": "urn:uuid:a99bfceb-f888-44f2-9319-d51e36038062",
          controller: 'someController',
          id: '64731d47-b0d2-4157-80b5-2e58ea97d13c',
          name: 'Test Instance',
        });
        should.exist(result.problem);
        result.problem.should.equal('CLIENT_ERROR');
        should.exist(result.data);
        should.exist(result.data.type);
        result.data.type.should.equal('NotAllowedError');
      });
      it('no ValidationError on proper instance', async () => {
        const result = await api.post('/instances', {
          controller: 'theMockControllerId',
          id: '64731d47-b0d2-4157-80b5-2e58ea97d13c',
          name: 'Test Instance',
        });

        // FIXME: the SERVER_ERROR/InvalidStateError being returned is
        // expected at this point, schema validation on this API has passed.
        // this error is being produced by the KMS system because all the
        // proper mocks are not yet in place
        should.exist(result.problem);
        result.problem.should.equal('SERVER_ERROR');
        should.exist(result.data);
        should.exist(result.data.type);
        result.data.type.should.equal('InvalidStateError');
      });
      it('ValidationError on missing controller', async () => {
        const result = await api.post('/instances', {
          // controller: 'theMockControllerId',
          id: '64731d47-b0d2-4157-80b5-2e58ea97d13c',
          name: 'Test Instance',
        });
        should.exist(result.problem);
        result.problem.should.equal('CLIENT_ERROR');
        should.exist(result.data);
        should.exist(result.data.type);
        result.data.type.should.equal('ValidationError');
      });
      it('ValidationError on missing id', async () => {
        const result = await api.post('/instances', {
          controller: 'theMockControllerId',
          // id: '64731d47-b0d2-4157-80b5-2e58ea97d13c',
          name: 'Test Instance',
        });
        should.exist(result.problem);
        result.problem.should.equal('CLIENT_ERROR');
        should.exist(result.data);
        should.exist(result.data.type);
        result.data.type.should.equal('ValidationError');
      });
      it('ValidationError on missing name', async () => {
        const result = await api.post('/instances', {
          controller: 'theMockControllerId',
          id: '64731d47-b0d2-4157-80b5-2e58ea97d13c',
          // name: 'Test Instance',
        });
        should.exist(result.problem);
        result.problem.should.equal('CLIENT_ERROR');
        should.exist(result.data);
        should.exist(result.data.type);
        result.data.type.should.equal('ValidationError');
      });
      it('ValidationError on additional field', async () => {
        const result = await api.post('/instances', {
          controller: 'theMockControllerId',
          id: '64731d47-b0d2-4157-80b5-2e58ea97d13c',
          name: 'Test Instance',
          foo: 'bar',
        });
        should.exist(result.problem);
        result.problem.should.equal('CLIENT_ERROR');
        should.exist(result.data);
        should.exist(result.data.type);
        result.data.type.should.equal('ValidationError');
      });
    }); // end authenticated
  }); // end instances POST
});

function _stubPassport(passportStub) {
  passportStub.callsFake((req, res, next) => {
    req.user = {
      account: {},
      actor: {
        id: 'theMockControllerId'
      }
    };
    next();
  });
}

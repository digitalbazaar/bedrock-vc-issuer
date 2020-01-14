/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const {create} = require('apisauce');
const {httpsAgent} = require('bedrock-https-agent');
const sinon = require('sinon');
const brPassport = require('bedrock-passport');

const api = create({
  baseURL: `${config.server.baseUri}/vc-issuer`,
  httpsAgent,
  timeout: 1000,
});

describe('API', () => {
  describe('instances endpoint', () => {
    describe('unauthenticated', () => {
      it('GET returns NotAllowedError', async () => {
        const result = await api.get('/instances');
        should.exist(result.problem);
        result.problem.should.equal('CLIENT_ERROR');
        should.exist(result.data);
        should.exist(result.data.type);
        result.data.type.should.equal('NotAllowedError');
      });
      it('POST returns NotAllowedError', async () => {
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
      it('GET returns ', async () => {
        const result = await api.get('/instances');
        should.not.exist(result.problem);
        console.log('DDDDDdd', result.data);
      });
    }); // end authenticated
  });
});

function _stubPassport(passportStub) {
  passportStub.callsFake((req, res, next) => {
    req.user = {
      account: {}
    };
    next();
  });
}

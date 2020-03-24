/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const {create} = require('apisauce');
const {httpsAgent} = require('bedrock-https-agent');
// const sinon = require('sinon');
// const brPassport = require('bedrock-passport');

const api = create({
  baseURL: `${config.server.baseUri}/credentials`,
  httpsAgent,
  timeout: 1000,
});

// FIXME: using embedded context:
// https://www.w3.org/2018/credentials/examples/v1
// is this context supposed to be supported in a documentLoader
// it has been dropped from the credentials-context package
const mockCredential = require('./mock-credential');

describe('Interop Credentials API', () => {
  it('issues a credential', async () => {
    const result = await api.post('/issueCredential', {
      credential: mockCredential
    });
    should.exist(result.data.proof);
  });
});

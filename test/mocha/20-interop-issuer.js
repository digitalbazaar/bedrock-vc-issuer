/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const {create} = require('apisauce');
const {httpsAgent} = require('bedrock-https-agent');

const api = create({
  baseURL: `${config.server.baseUri}/credentials`,
  httpsAgent,
  timeout: 1000,
});

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential');

describe('Interop Credentials API', () => {
  it('issues a credential', async () => {
    let error;
    let result;
    try {
      result = await api.post('/issueCredential', {
        credential: mockCredential
      });
    } catch(e) {
      error = e;
    }
    should.not.exist(error);
    // apisauce API does not throw it puts errors in `result.problem`
    should.not.exist(result.problem);
    should.exist(result.data.proof);
  });
});

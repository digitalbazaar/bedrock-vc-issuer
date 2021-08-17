/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const {create} = require('apisauce');
const {httpsAgent} = require('bedrock-https-agent');
const helpers = require('./helpers.js');

const api = create({
  baseURL: `${config.server.baseUri}/vc-issuer`,
  httpsAgent,
  timeout: 1000,
});
const privateKmsBaseUrl = `${config.server.baseUri}/kms`;
const publicKmsBaseUrl = `${config.server.baseUri}/kms`;

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential');

describe('Interop Credentials API', () => {
  let agents;
  before(async function() {
    const accountId = 'urn:uuid:43f47a1f-acaf-4dd1-8597-001a8b0637e6';
    agents = await helpers.insertIssuerAgent({
      id: accountId,
      token: 'token-43f47a1f-acaf-4dd1-8597-001a8b0637e6',
      didMethod: 'key',
      publicKmsBaseUrl,
      privateKmsBaseUrl
    });
  });
  it('issues a credential', async () => {
    const {integration: {secrets}} = agents;
    let error;
    let result;
    const {token} = secrets;
    try {
      result = await api.post(
        '/issue',
        {credential: mockCredential},
        {headers: {Authorization: `Bearer ${token}`}}
      );
    } catch(e) {
      error = e;
    }
    should.not.exist(error);
    // apisauce API does not throw it puts errors in `result.problem`
    should.not.exist(result.problem);
    const {proof} = result.data.verifiableCredential;
    should.exist(proof);
  });
});

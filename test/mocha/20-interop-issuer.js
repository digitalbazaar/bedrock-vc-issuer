/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const {httpsAgent} = require('bedrock-https-agent');
const {httpClient} = require('@digitalbazaar/http-client');
const helpers = require('./helpers.js');

const privateKmsBaseUrl = `${config.server.baseUri}/kms`;
const publicKmsBaseUrl = `${config.server.baseUri}/kms`;

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential');
const baseURL = `${config.server.baseUri}/vc-issuer`;
const timeout = 10000;

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
      result = await httpClient.post(`${baseURL}/issue`, {
        headers: {Authorization: `Bearer ${token}`},
        json: {credential: mockCredential},
        agent: httpsAgent,
        timeout
      });
    } catch(e) {
      error = e;
    }
    should.not.exist(error);
    should.exist(result);
    const {proof} = result.data.verifiableCredential;
    should.exist(proof);
  });
});

/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from '../helpers.js';
import {agent} from '@bedrock/https-agent';
import {createRequire} from 'node:module';
import {httpClient} from '@digitalbazaar/http-client';
import {klona} from 'klona';

const require = createRequire(import.meta.url);

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('../mock-credential.json');

export function testIssueWithOAuth2({suiteName, algorithm, issueOptions}) {
  const depOptions = {
    status: false,
    suiteOptions: {
      suiteName, algorithm, issueOptions
    },
    cryptosuites: [{
      name: suiteName,
      algorithm
    }],
    zcaps: true
  };
  describe('issue using oauth2', function() {
    let capabilityAgent;
    let zcaps;
    let oauth2IssuerConfig;
    before(async () => {
      // provision dependencies
      ({capabilityAgent, zcaps} = await helpers.provisionDependencies(
        depOptions));

      // create issuer instance w/ oauth2-based authz
      oauth2IssuerConfig = await helpers.createIssuerConfig(
        {capabilityAgent, zcaps, oauth2: true, suiteName});
    });
    describe('/credentials/issue', () => {
      it('issues a valid credential w/oauth2 w/root scope', async () => {
        const credential = klona(mockCredential);
        let error;
        let result;
        try {
          const configId = oauth2IssuerConfig.id;
          const url = `${configId}/credentials/issue`;
          const accessToken = await helpers.getOAuth2AccessToken(
            {configId, action: 'write', target: '/'});
          result = await httpClient.post(url, {
            agent,
            headers: {authorization: `Bearer ${accessToken}`},
            json: {credential, options: issueOptions}
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
      it('issues a valid credential w/oauth2 w/credentials scope',
        async () => {
          const credential = klona(mockCredential);
          let error;
          let result;
          try {
            const configId = oauth2IssuerConfig.id;
            const url = `${configId}/credentials/issue`;
            const accessToken = await helpers.getOAuth2AccessToken(
              {configId, action: 'write', target: '/credentials'});
            result = await httpClient.post(url, {
              agent,
              headers: {authorization: `Bearer ${accessToken}`},
              json: {credential, options: issueOptions}
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
      it('issues a valid credential w/oauth2 w/targeted scope', async () => {
        const credential = klona(mockCredential);
        let error;
        let result;
        try {
          const configId = oauth2IssuerConfig.id;
          const url = `${configId}/credentials/issue`;
          const accessToken = await helpers.getOAuth2AccessToken(
            {configId, action: 'write', target: '/credentials/issue'});
          result = await httpClient.post(url, {
            agent,
            headers: {authorization: `Bearer ${accessToken}`},
            json: {credential, options: issueOptions}
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
      it('fails to issue a valid credential w/bad action scope', async () => {
        const credential = klona(mockCredential);
        let error;
        let result;
        try {
          const configId = oauth2IssuerConfig.id;
          const url = `${configId}/credentials/issue`;
          const accessToken = await helpers.getOAuth2AccessToken(
            // wrong action: `read`
            {configId, action: 'read', target: '/credentials/issue'});
          result = await httpClient.post(url, {
            agent,
            headers: {authorization: `Bearer ${accessToken}`},
            json: {credential, options: issueOptions}
          });
        } catch(e) {
          error = e;
        }
        should.exist(error);
        should.not.exist(result);
        error.status.should.equal(403);
        error.data.type.should.equal('NotAllowedError');
        should.exist(error.data.cause);
        should.exist(error.data.cause.details);
        should.exist(error.data.cause.details.code);
        error.data.cause.details.code.should.equal(
          'ERR_JWT_CLAIM_VALIDATION_FAILED');
        should.exist(error.data.cause.details.claim);
        error.data.cause.details.claim.should.equal('scope');
      });
      it('fails to issue a valid credential w/bad path scope', async () => {
        const credential = klona(mockCredential);
        let error;
        let result;
        try {
          const configId = oauth2IssuerConfig.id;
          const url = `${configId}/credentials/issue`;
          const accessToken = await helpers.getOAuth2AccessToken(
            // wrong path: `/foo`
            {configId, action: 'write', target: '/foo'});
          result = await httpClient.post(url, {
            agent,
            headers: {authorization: `Bearer ${accessToken}`},
            json: {credential, options: issueOptions}
          });
        } catch(e) {
          error = e;
        }
        should.exist(error);
        should.not.exist(result);
        error.status.should.equal(403);
        error.data.type.should.equal('NotAllowedError');
        should.exist(error.data.cause);
        should.exist(error.data.cause.details);
        should.exist(error.data.cause.details.code);
        error.data.cause.details.code.should.equal(
          'ERR_JWT_CLAIM_VALIDATION_FAILED');
        should.exist(error.data.cause.details.claim);
        error.data.cause.details.claim.should.equal('scope');
      });
    });
  });
}

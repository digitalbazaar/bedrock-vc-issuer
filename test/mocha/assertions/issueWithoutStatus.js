/*
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as assertions from './index.js';
import * as helpers from '../helpers.js';
import {createRequire} from 'node:module';
import {klona} from 'klona';

const require = createRequire(import.meta.url);

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('../mock-credential.json');
const mockCredentialV2 = require('../mock-credential-v2.json');

export function testIssueWithoutStatus({
  suiteName, algorithm, issueOptions, tags
}) {
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
  describe('issue with no status', function() {
    let issuer;
    let capabilityAgent;
    let zcaps;
    let noStatusListIssuerId;
    let noStatusListIssuerRootZcap;
    before(async () => {
      // provision dependencies
      const {cryptosuites} = depOptions;
      ({issuer, capabilityAgent, zcaps} = await helpers.provisionDependencies(
        depOptions));

      // create issuer instance w/ no status list options
      const issueOptions = helpers.createIssueOptions({issuer, cryptosuites});
      const noStatusListIssuerConfig = await helpers.createIssuerConfig(
        {capabilityAgent, zcaps, issueOptions});
      noStatusListIssuerId = noStatusListIssuerConfig.id;
      noStatusListIssuerRootZcap = helpers.createRootZcap({
        url: noStatusListIssuerId
      });
    });
    it('issues a valid credential w/no "credentialStatus"', async () => {
      const credential = klona(mockCredential);
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      const {verifiableCredential} = await assertions.issueAndAssert({
        configId: noStatusListIssuerId,
        credential,
        issueOptions,
        zcapClient,
        capability: noStatusListIssuerRootZcap
      });
      should.exist(verifiableCredential.id);
      should.not.exist(verifiableCredential.credentialStatus);
      // `created` should not be set by default because new issue config
      // mechanism was used w/o requesting it
      should.not.exist(verifiableCredential.proof.created);
    });
    it('issues a VC 2.0 credential w/no "credentialStatus"', async () => {
      const credential = klona(mockCredentialV2);
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      const {verifiableCredential} = await assertions.issueAndAssert({
        configId: noStatusListIssuerId,
        credential,
        issueOptions,
        zcapClient,
        capability: noStatusListIssuerRootZcap
      });
      should.exist(verifiableCredential.id);
      should.not.exist(verifiableCredential.credentialStatus);
      // `created` should not be set by default because new issue config
      // mechanism was used w/o requesting it
      should.not.exist(verifiableCredential.proof.created);
    });

    it('fails to issue an empty credential', async () => {
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

    it('fails to issue a VC missing a "credentialSchema" type', async () => {
      const credential = klona(mockCredentialV2);
      // `type` is not present, so a validation error should occur
      credential.credentialSchema = {
        id: 'https://example.com#schema'
      };

      let error;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        await zcapClient.write({
          url: `${noStatusListIssuerId}/credentials/issue`,
          capability: noStatusListIssuerRootZcap,
          json: {credential}
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      error.data.name.should.equal('ValidationError');
      should.exist(error.data.details?.errors?.[0]);
      const typeError = error.data.details.errors[0];
      typeError.name.should.equal('ValidationError');
      typeError.details.path.should.equal('.credential.credentialSchema');
      typeError.details.params.missingProperty.should.equal('type');
    });
  });

  // only add additional tests if testing `general` behavior
  if(!tags?.includes('general')) {
    return;
  }

  const depOptionsWithCreated = {
    status: false,
    suiteOptions: {
      suiteName, algorithm, issueOptions
    },
    cryptosuites: [{
      name: suiteName,
      algorithm,
      options: {
        includeCreated: true
      }
    }],
    zcaps: true
  };
  describe('issue with no status and include "created"', function() {
    let issuer;
    let capabilityAgent;
    let zcaps;
    let noStatusListIssuerId;
    let noStatusListIssuerRootZcap;
    before(async () => {
      // provision dependencies
      const {cryptosuites} = depOptionsWithCreated;
      ({issuer, capabilityAgent, zcaps} = await helpers.provisionDependencies(
        depOptionsWithCreated));

      // create issuer instance w/ no status list options
      const issueOptions = helpers.createIssueOptions({issuer, cryptosuites});
      const noStatusListIssuerConfig = await helpers.createIssuerConfig(
        {capabilityAgent, zcaps, issueOptions});
      noStatusListIssuerId = noStatusListIssuerConfig.id;
      noStatusListIssuerRootZcap = helpers.createRootZcap({
        url: noStatusListIssuerId
      });
    });
    it('issues a valid credential w/no "credentialStatus"', async () => {
      const credential = klona(mockCredential);
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      const {verifiableCredential} = await assertions.issueAndAssert({
        configId: noStatusListIssuerId,
        credential,
        issueOptions,
        zcapClient,
        capability: noStatusListIssuerRootZcap
      });
      should.exist(verifiableCredential.id);
      should.not.exist(verifiableCredential.credentialStatus);
      // `created` should be set because it was requested
      should.exist(verifiableCredential.proof.created);
    });
    it('issues a VC 2.0 credential w/no "credentialStatus"', async () => {
      const credential = klona(mockCredentialV2);
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      const {verifiableCredential} = await assertions.issueAndAssert({
        configId: noStatusListIssuerId,
        credential,
        issueOptions,
        zcapClient,
        capability: noStatusListIssuerRootZcap
      });
      should.exist(verifiableCredential.id);
      should.not.exist(verifiableCredential.credentialStatus);
      // `created` should be set because it was requested
      should.exist(verifiableCredential.proof.created);
    });
  });
}

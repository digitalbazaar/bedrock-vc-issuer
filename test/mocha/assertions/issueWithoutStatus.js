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

export function testIssueWithoutStatus({suiteName, algorithm, issueOptions}) {
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
    let capabilityAgent;
    let zcaps;
    let noStatusListIssuerId;
    let noStatusListIssuerRootZcap;
    before(async () => {
      // provision dependencies
      ({capabilityAgent, zcaps} = await helpers.provisionDependencies(
        depOptions));

      // create issuer instance w/ no status list options
      const noStatusListIssuerConfig = await helpers.createIssuerConfig(
        {capabilityAgent, zcaps, suiteName});
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
  });
}

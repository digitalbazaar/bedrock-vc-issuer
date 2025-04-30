/*!
 * Copyright (c) 2020-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as assertions from './index.js';
import * as helpers from '../helpers.js';
import {createRequire} from 'node:module';

const require = createRequire(import.meta.url);

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('../mock-credential.json');

export function testIssueXi({suiteName, algorithm, issueOptions}) {
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
  describe('issue using extra information options', function() {
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
    it('issues a valid credential w/ "options.extraInformation"', async () => {
      const credential = structuredClone(mockCredential);
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      const extraInformationBytes = new Uint8Array([
        12, 52, 75, 63, 74, 85, 21, 5, 62, 10
      ]);
      const extraInformationEncoded = Buffer.from(
        extraInformationBytes).toString('base64url');
      const {verifiableCredential} = await assertions.issueAndAssert({
        configId: noStatusListIssuerId,
        credential,
        issueOptions: {
          ...issueOptions,
          extraInformation: extraInformationEncoded
        },
        zcapClient,
        capability: noStatusListIssuerRootZcap
      });
      should.exist(verifiableCredential.id);
      should.not.exist(verifiableCredential.credentialStatus);
    });
    it('fails to issue a valid credential w/ invalid ' +
      '"options.extraInformation"', async () => {
      let error;
      try {
        const credential = structuredClone(mockCredential);
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        await zcapClient.write({
          url: `${noStatusListIssuerId}/credentials/issue`,
          capability: noStatusListIssuerRootZcap,
          json: {
            credential,
            options: {
              ...issueOptions,
              extraInformation: ['notAString']
            }
          }
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      error.data.name.should.equal('ValidationError');
    });
  });
}

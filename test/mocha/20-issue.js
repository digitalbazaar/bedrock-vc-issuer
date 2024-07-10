/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {testBitstringStatusList} from './assertions/testBitstringStatusList.js';
import {testIssueCrashRecovery} from './assertions/testIssueCrashRecovery.js';
import {testIssueSd} from './assertions/testIssueSd.js';
import {testIssueWithOAuth2} from './assertions/issueWithOAuth2.js';
import {testIssueWithoutStatus} from './assertions/issueWithoutStatus.js';
import {testIssueXi} from './assertions/testIssueXi.js';
import {testStatusScaling} from './assertions/testStatusScaling.js';
import {
  testTerseBitstringStatusList
} from './assertions/testTerseBitstringStatusList.js';

describe('issue', () => {
  describe('eddsa-rdfc-2022', () => {
    const options = {
      suiteName: 'eddsa-rdfc-2022',
      algorithm: 'Ed25519',
      issueOptions: {},
      statusOptions: {}
    };
    testIssueWithoutStatus(options);
    testBitstringStatusList(options);
    testTerseBitstringStatusList(options);

    // to reduce runtime and because a different suite should not change
    // the results, only this suite runs against these tests
    testIssueWithOAuth2(options);
    testIssueCrashRecovery(options);
    testStatusScaling(options);
  });

  describe('ecdsa-rdfc-2019, P-256', () => {
    const options = {
      suiteName: 'ecdsa-rdfc-2019',
      algorithm: 'P-256',
      issueOptions: {},
      statusOptions: {}
    };
    testIssueWithoutStatus(options);
    testBitstringStatusList(options);
    testTerseBitstringStatusList(options);
  });

  describe('ecdsa-rdfc-2019, P-384', () => {
    const options = {
      suiteName: 'ecdsa-rdfc-2019',
      algorithm: 'P-384',
      issueOptions: {},
      statusOptions: {}
    };
    testIssueWithoutStatus(options);
    testBitstringStatusList(options);
    testTerseBitstringStatusList(options);
  });

  describe('ecdsa-sd-2023', () => {
    const options = {
      suiteName: 'ecdsa-sd-2023',
      algorithm: 'P-256',
      issueOptions: {},
      statusOptions: {
        // sign status list with simple ECDSA
        suiteName: 'ecdsa-rdfc-2019',
        algorithm: 'P-256'
      },
      terseIssueOptions: {mandatoryPointers: ['/issuer']}
    };
    testIssueWithoutStatus(options);
    testBitstringStatusList(options);
    testTerseBitstringStatusList(options);
  });

  describe('bbs-2023', () => {
    const options = {
      suiteName: 'bbs-2023',
      algorithm: 'Bls12381G2',
      issueOptions: {},
      statusOptions: {
        // sign status list with simple ECDSA
        suiteName: 'ecdsa-rdfc-2019',
        algorithm: 'P-256'
      },
      terseIssueOptions: {mandatoryPointers: ['/issuer']}
    };
    testIssueWithoutStatus(options);
    testIssueSd(options);
    testBitstringStatusList(options);
    testTerseBitstringStatusList(options);
  });

  describe('ecdsa-xi-2023, P-256', () => {
    const options = {
      suiteName: 'ecdsa-xi-2023',
      algorithm: 'P-256',
      issueOptions: {
        extraInformation: 'abc'
      },
      statusOptions: {
        // sign status list with simple ECDSA
        suiteName: 'ecdsa-rdfc-2019',
        algorithm: 'P-256'
      }
    };

    testIssueWithoutStatus(options);
    testIssueXi(options);
    testBitstringStatusList(options);
    testTerseBitstringStatusList(options);
  });

  describe('Ed25519Signature2020', () => {
    const options = {
      suiteName: 'Ed25519Signature2020',
      algorithm: 'Ed25519',
      issueOptions: {},
      statusOptions: {}
    };
    testIssueWithoutStatus(options);
    testBitstringStatusList(options);
    testTerseBitstringStatusList(options);
  });
});

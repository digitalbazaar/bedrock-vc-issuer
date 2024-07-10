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
  const suites = {
    'eddsa-rdfc-2022': {
      suiteName: 'eddsa-rdfc-2022',
      algorithm: 'Ed25519',
      issueOptions: {},
      statusOptions: {},
      tags: ['general']
    },
    'ecdsa-rdfc-2019, P-256': {
      suiteName: 'ecdsa-rdfc-2019',
      algorithm: 'P-256',
      issueOptions: {},
      statusOptions: {},
      tags: []
    },
    'ecdsa-rdfc-2019, P-384': {
      suiteName: 'ecdsa-rdfc-2019',
      algorithm: 'P-384',
      issueOptions: {},
      statusOptions: {},
      tags: []
    },
    'ecdsa-sd-2023': {
      suiteName: 'ecdsa-sd-2023',
      algorithm: 'P-256',
      issueOptions: {},
      statusOptions: {
        // sign status list with simple ECDSA
        suiteName: 'ecdsa-rdfc-2019',
        algorithm: 'P-256'
      },
      terseIssueOptions: {mandatoryPointers: ['/issuer']},
      tags: ['sd']
    },
    'bbs-2023': {
      suiteName: 'bbs-2023',
      algorithm: 'Bls12381G2',
      issueOptions: {},
      statusOptions: {
        // sign status list with simple ECDSA
        suiteName: 'ecdsa-rdfc-2019',
        algorithm: 'P-256'
      },
      terseIssueOptions: {mandatoryPointers: ['/issuer']},
      tags: ['sd']
    },
    'ecdsa-xi-2023': {
      suiteName: 'ecdsa-xi-2023',
      algorithm: 'P-256',
      issueOptions: {
        extraInformation: 'abc'
      },
      statusOptions: {
        // sign status list with simple ECDSA
        suiteName: 'ecdsa-rdfc-2019',
        algorithm: 'P-256'
      },
      tags: ['xi']
    },
    Ed25519Signature2020: {
      suiteName: 'Ed25519Signature2020',
      algorithm: 'Ed25519',
      issueOptions: {},
      statusOptions: {},
      tags: []
    }
  };

  // enable setting 'only' tag
  let suitesToRun = Object.values(suites)
    .filter(({tags}) => tags?.includes('only'))
    .map(({suiteName}) => suiteName);
  if(suitesToRun.length === 0) {
    suitesToRun = Object.keys(suites);
  }

  for(const name of suitesToRun) {
    const options = suites[name];
    describe(name, () => {
      // these tests run for every suite
      testIssueWithoutStatus(options);
      testBitstringStatusList(options);
      testTerseBitstringStatusList(options);

      // to reduce runtime and because a different suite should not change
      // the results, only suites marked "general" run these tests
      if(options.tags?.includes('general')) {
        testIssueWithOAuth2(options);
        testIssueCrashRecovery(options);
        testStatusScaling(options);
      }

      // tests that run for SD suites only
      if(options.tags?.includes('sd')) {
        testIssueSd(options);
      }

      // tests that run for XI suites only
      if(options.tags?.includes('xi')) {
        testIssueXi(options);
      }
    });
  }
});

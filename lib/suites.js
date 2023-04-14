/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {
  cryptosuite as ecdsa2019CryptoSuite
} from '@digitalbazaar/ecdsa-2019-cryptosuite';
import {Ed25519Signature2018} from '@digitalbazaar/ed25519-signature-2018';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {
  cryptosuite as eddsa2022CryptoSuite
} from '@digitalbazaar/eddsa-2022-cryptosuite';

const SUPPORTED_SUITES = new Map([
  ['Ed25519Signature2020', {
    keyType: 'Ed25519',
    createSuite: ({signer}) => new Ed25519Signature2020({signer})
  }],
  ['Ed25519Signature2018', {
    keyType: 'Ed25519',
    createSuite: ({signer}) => new Ed25519Signature2018({signer})
  }],
  [eddsa2022CryptoSuite.name, {
    keyType: 'Ed25519',
    createSuite: _createEddsa2022Suite
  }],
  [ecdsa2019CryptoSuite.name, {
    keyType: 'P-256',
    createSuite: _createEcdsa2019Suite
  }]
]);

export function getSuiteParams({config, suiteName}) {
  // ensure suite is supported
  const suiteInfo = SUPPORTED_SUITES.get(suiteName);
  if(!suiteInfo) {
    throw new Error(`Unsupported suite "${suiteName}".`);
  }

  // get zcap to use to invoke assertion method key
  const {keyType, createSuite} = suiteInfo;
  const referenceId = `assertionMethod:${keyType}`;
  let zcap = config.zcaps[referenceId];

  // For backwards compatibility, check for lowercased keytype ed25519
  if(!zcap && referenceId === 'assertionMethod:Ed25519') {
    zcap = config.zcaps['assertionMethod:ed25519'];
  }

  if(!zcap) {
    throw new Error(
      `No capability available to sign using suite "${suiteName}".`);
  }

  return {zcap, createSuite, referenceId};
}

function _createEddsa2022Suite({signer}) {
  // remove milliseconds precision
  const date = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const cryptosuite = eddsa2022CryptoSuite;
  return new DataIntegrityProof({signer, date, cryptosuite});
}

function _createEcdsa2019Suite({signer}) {
  // remove milliseconds precision
  const date = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const cryptosuite = ecdsa2019CryptoSuite;
  return new DataIntegrityProof({signer, date, cryptosuite});
}

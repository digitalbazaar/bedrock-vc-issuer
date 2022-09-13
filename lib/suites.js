/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {Ed25519Signature2018} from '@digitalbazaar/ed25519-signature-2018';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {
  cryptosuite as eddsa2022CryptoSuite
} from '@digitalbazaar/eddsa-2022-cryptosuite';

export const createEddsa2022Suite = async ({signer}) => {
  const keyDescription = await signer.getKeyDescription();
  // replace the milliseconds value with Z
  const date = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const cryptosuite = eddsa2022CryptoSuite;
  const multiKey = await Ed25519Multikey.from(keyDescription);
  return new DataIntegrityProof({signer: multiKey.signer(), date, cryptosuite});
};

const SUPPORTED_SUITES = new Map([
  ['Ed25519Signature2020', {
    keyType: 'ed25519', createSuite:
      ({signer}) => new Ed25519Signature2020({signer})
  }],
  ['Ed25519Signature2018', {
    keyType: 'ed25519', createSuite:
      ({signer}) => new Ed25519Signature2018({signer})
  }],
  [eddsa2022CryptoSuite.name, {
    keyType: 'ed25519', createSuite: createEddsa2022Suite
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
  const zcap = config.zcaps[referenceId];
  if(!zcap) {
    throw new Error(
      `No capability available to sign using suite "${suiteName}".`);
  }

  return {zcap, createSuite, referenceId};
}

/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {
  cryptosuite as eddsa2022CryptoSuite
} from '@digitalbazaar/eddsa-2022-cryptosuite';

export const createEddsa2022Suite = async ({signer}) => {
  // replace the milliseconds value with Z
  const date = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const cryptosuite = eddsa2022CryptoSuite;
  const multiKeySigner = await Ed25519Multikey.from(signer);
  return new DataIntegrityProof({signer: multiKeySigner, date, cryptosuite});
};

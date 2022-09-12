/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */

import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {
  cryptosuite as eddsa2022CryptoSuite
} from '@digitalbazaar/eddsa-2022-cryptosuite';

export class Eddsa2022Suite extends DataIntegrityProof {
  constructor(args) {
    // replace the milliseconds value with Z
    const date = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
    const cryptosuite = eddsa2022CryptoSuite;
    super({...args, date, cryptosuite});
  }
}

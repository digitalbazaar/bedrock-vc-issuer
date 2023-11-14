/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {
  createSignCryptosuite as createEcdsaSd2023SignCryptosuite
} from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {
  cryptosuite as ecdsa2019CryptoSuite
} from '@digitalbazaar/ecdsa-2019-cryptosuite';
import {
  cryptosuite as ecdsaRdfc2019CryptoSuite
} from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import {Ed25519Signature2018} from '@digitalbazaar/ed25519-signature-2018';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {
  cryptosuite as eddsa2022CryptoSuite
} from '@digitalbazaar/eddsa-2022-cryptosuite';
import {
  cryptosuite as eddsaRdfc2022CryptoSuite
} from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import {v4 as uuid} from 'uuid';

const SUPPORTED_SUITES = new Map([
  ['Ed25519Signature2020', {
    createSuite: ({signer}) => new Ed25519Signature2020({signer})
  }],
  ['Ed25519Signature2018', {
    createSuite: ({signer}) => new Ed25519Signature2018({signer})
  }],
  [eddsa2022CryptoSuite.name, {
    createSuite: _createEddsa2022Suite
  }],
  [ecdsa2019CryptoSuite.name, {
    createSuite: _createEcdsa2019Suite
  }],
  [eddsaRdfc2022CryptoSuite.name, {
    createSuite: _createEddsaRdfc2022Suite
  }],
  [ecdsaRdfc2019CryptoSuite.name, {
    createSuite: _createEcdsaRdfc2019Suite
  }],
  [createEcdsaSd2023SignCryptosuite().name, {
    createSuite: _createEcdsaSd2023Suite
  }]
]);

export function getSuiteParams({config, suiteName}) {
  // ensure suite is supported
  const suiteInfo = SUPPORTED_SUITES.get(suiteName);
  if(!suiteInfo) {
    throw new Error(`Unsupported suite "${suiteName}".`);
  }

  // get zcap to use to invoke assertion method key
  const {createSuite} = suiteInfo;
  let referenceId = 'assertionMethod';
  let zcap = config.zcaps[referenceId];

  // older reference ID formats to check for backwards compatibility
  const olderReferenceIdFormats = [
    'assertionMethod:Ed25519',
    'assertionMethod:ed25519',
    'assertionMethod:P-256'
  ];
  if(!zcap) {
    for(const referenceIdFormat of olderReferenceIdFormats) {
      if(config.zcaps[referenceIdFormat]) {
        referenceId = referenceIdFormat;
        zcap = config.zcaps[referenceId];
        break; // exit if a valid zcap is found
      }
    }
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
  return new DataIntegrityProof({
    signer, date, cryptosuite, legacyContext: true
  });
}

function _createEcdsa2019Suite({signer} = {}) {
  // remove milliseconds precision
  const date = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const cryptosuite = ecdsa2019CryptoSuite;
  return new DataIntegrityProof({
    signer, date, cryptosuite, legacyContext: true
  });
}

function _createEddsaRdfc2022Suite({signer}) {
  // remove milliseconds precision
  const date = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const cryptosuite = eddsaRdfc2022CryptoSuite;
  return new DataIntegrityProof({signer, date, cryptosuite});
}

function _createEcdsaRdfc2019Suite({signer} = {}) {
  // remove milliseconds precision
  const date = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const cryptosuite = ecdsaRdfc2019CryptoSuite;
  return new DataIntegrityProof({signer, date, cryptosuite});
}

function _createEcdsaSd2023Suite({signer} = {}) {
  // remove milliseconds precision
  const date = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const cryptosuite = createEcdsaSd2023SignCryptosuite({
    mandatoryPointers: [
      '/issuer',
      '/issuanceDate'
    ]
  });
  const diProof = new DataIntegrityProof({signer, date, cryptosuite});
  diProof.proof = {id: `urn:uuid:${uuid()}`};
  return diProof;
}

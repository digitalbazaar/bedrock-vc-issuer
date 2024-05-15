/*!
 * Copyright (c) 2019-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import {
  createSignCryptosuite as createBbs2023SignCryptosuite
} from '@digitalbazaar/bbs-2023-cryptosuite';
import {
  createSignCryptosuite as createEcdsaSd2023SignCryptosuite
} from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import {
  createCryptosuite as createEcdsaXi2023SignCryptosuite
} from '@digitalbazaar/ecdsa-xi-2023-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {decode} from 'base64url-universal';
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
  }],
  [createEcdsaXi2023SignCryptosuite().name, {
    createSuite: _createEcdsaXi2023Suite
  }],
  [createBbs2023SignCryptosuite().name, {
    createSuite: _createBbs2023Suite
  }],
]);

const {util: {BedrockError}} = bedrock;

export function getSuiteParams({config, suiteName, cryptosuite}) {
  // get zcap to use to invoke assertion method key
  let zcap;
  let referenceId;
  if(cryptosuite) {
    suiteName = cryptosuite.name;
    referenceId = cryptosuite.zcapReferenceIds.assertionMethod;
    zcap = config.zcaps[referenceId];
  } else {
    referenceId = 'assertionMethod';
    zcap = config.zcaps[referenceId];
    if(!zcap) {
      // older reference ID formats to check for backwards compatibility
      const olderReferenceIdFormats = [
        'assertionMethod:Ed25519',
        'assertionMethod:ed25519',
        'assertionMethod:P-256'
      ];
      for(const referenceIdFormat of olderReferenceIdFormats) {
        if(config.zcaps[referenceIdFormat]) {
          referenceId = referenceIdFormat;
          zcap = config.zcaps[referenceId];
          // break if a valid zcap is found
          break;
        }
      }
    }
  }

  // ensure suite is supported
  const suiteInfo = SUPPORTED_SUITES.get(suiteName);
  if(!suiteInfo) {
    throw new BedrockError(`Unsupported suite "${suiteName}".`, {
      name: 'NotSupportedError',
      details: {
        httpStatusCode: 500,
        public: true
      }
    });
  }

  // ensure zcap for assertion method is available
  if(!zcap) {
    throw new BedrockError(
      `No capability available to sign using suite "${suiteName}".`, {
        name: 'DataError',
        details: {
          httpStatusCode: 500,
          public: true
        }
      });
  }

  const {createSuite} = suiteInfo;
  return {zcap, createSuite, referenceId};
}

function _createEddsa2022Suite({signer}) {
  return new DataIntegrityProof({
    signer,
    date: _getISODateTime(),
    cryptosuite: eddsa2022CryptoSuite,
    legacyContext: true
  });
}

function _createEcdsa2019Suite({signer} = {}) {
  return new DataIntegrityProof({
    signer,
    date: _getISODateTime(),
    cryptosuite: ecdsa2019CryptoSuite,
    legacyContext: true
  });
}

function _createEddsaRdfc2022Suite({signer}) {
  return new DataIntegrityProof({
    signer,
    date: _getISODateTime(),
    cryptosuite: eddsaRdfc2022CryptoSuite
  });
}

function _createEcdsaRdfc2019Suite({signer} = {}) {
  return new DataIntegrityProof({
    signer,
    date: _getISODateTime(),
    cryptosuite: ecdsaRdfc2019CryptoSuite
  });
}

function _createEcdsaSd2023Suite({signer, options} = {}) {
  const mandatoryPointers = options?.mandatoryPointers ?? ['/issuer'];
  const cryptosuite = createEcdsaSd2023SignCryptosuite({
    mandatoryPointers
  });
  const diProof = new DataIntegrityProof({
    signer,
    date: _getISODateTime(),
    cryptosuite
  });
  diProof.proof = {id: `urn:uuid:${uuid()}`};
  return diProof;
}

function _createEcdsaXi2023Suite({signer, options} = {}) {
  if(options?.extraInformation === undefined) {
    throw new BedrockError('"options.extraInformation" is required.', {
      name: 'DataError',
      details: {
        httpStatusCode: 400,
        public: true
      }
    });
  }
  const extraInformation = decode(options.extraInformation);
  const cryptosuite = createEcdsaXi2023SignCryptosuite({
    extraInformation
  });
  return new DataIntegrityProof({
    signer,
    date: null,
    cryptosuite
  });
}

async function _createBbs2023Suite({signer, options} = {}) {
  // BBS requires signer public key
  const {publicKeyMultibase} = await signer.getKeyDescription();
  const {publicKey} = await Bls12381Multikey.from({publicKeyMultibase});
  signer.publicKey = publicKey;
  const mandatoryPointers = options?.mandatoryPointers ?? ['/issuer'];
  const cryptosuite = createBbs2023SignCryptosuite({
    mandatoryPointers
  });
  const diProof = new DataIntegrityProof({
    signer,
    date: _getISODateTime(),
    cryptosuite
  });
  diProof.proof = {id: `urn:uuid:${uuid()}`};
  return diProof;
}

function _getISODateTime(date = new Date()) {
  // remove milliseconds precision
  return date.toISOString().replace(/\.\d+Z$/, 'Z');
}

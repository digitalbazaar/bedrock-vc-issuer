/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import {
  createSignCryptosuite as createBbs2023SignCryptosuite
} from '@digitalbazaar/bbs-2023-cryptosuite';
import {
  createSignCryptosuite as createEcdsaJcs2019CryptoSuite
} from '@digitalbazaar/ecdsa-jcs-2019-cryptosuite';
import {
  createSignCryptosuite as createEcdsaSd2023SignCryptosuite
} from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import {
  createCryptosuite as createEcdsaXi2023SignCryptosuite
} from '@digitalbazaar/ecdsa-xi-2023-cryptosuite';
import {
  createSignCryptosuite as createEddsaJcs2022CryptoSuite
} from '@digitalbazaar/eddsa-jcs-2022-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {
  cryptosuite as ecdsaRdfc2019CryptoSuite
} from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {
  cryptosuite as eddsaRdfc2022CryptoSuite
} from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import {randomUUID as uuid} from 'node:crypto';

const SUPPORTED_SUITES = new Map([
  ['Ed25519Signature2020', {
    createSuite: ({signer}) => new Ed25519Signature2020({signer})
  }],
  [eddsaRdfc2022CryptoSuite.name, {
    createSuite: _createEddsaRdfc2022Suite
  }],
  [ecdsaRdfc2019CryptoSuite.name, {
    createSuite: _createEcdsaRdfc2019Suite
  }],
  [createEddsaJcs2022CryptoSuite().name, {
    createSuite: _createEddsaJcs2022Suite
  }],
  [createEcdsaJcs2019CryptoSuite().name, {
    createSuite: _createEcdsaJcs2019Suite
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
    // legacy mode, generate `cryptosuite`...
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
    cryptosuite = {
      name: suiteName,
      zcapReferenceIds: {
        assertionMethod: referenceId
      },
      options: {
        // legacy mode always includes `created`
        includeCreated: true
      }
    };
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
  return {zcap, createSuite, referenceId, cryptosuite};
}

function _createEddsaRdfc2022Suite({signer, cryptosuiteConfig}) {
  return new DataIntegrityProof({
    signer,
    date: _getCreated({cryptosuiteConfig}),
    cryptosuite: eddsaRdfc2022CryptoSuite
  });
}

function _createEcdsaRdfc2019Suite({signer, cryptosuiteConfig} = {}) {
  return new DataIntegrityProof({
    signer,
    date: _getCreated({cryptosuiteConfig}),
    cryptosuite: ecdsaRdfc2019CryptoSuite
  });
}

function _createEddsaJcs2022Suite({signer, cryptosuiteConfig}) {
  return new DataIntegrityProof({
    signer,
    date: _getCreated({cryptosuiteConfig}),
    cryptosuite: createEddsaJcs2022CryptoSuite()
  });
}

function _createEcdsaJcs2019Suite({signer, cryptosuiteConfig} = {}) {
  return new DataIntegrityProof({
    signer,
    date: _getCreated({cryptosuiteConfig}),
    cryptosuite: createEcdsaJcs2019CryptoSuite()
  });
}

function _createEcdsaSd2023Suite({signer, options, cryptosuiteConfig} = {}) {
  // enforce `cryptosuiteConfig.options` if given
  if(cryptosuiteConfig?.options?.mandatoryPointers &&
    options?.mandatoryPointers) {
    throw new BedrockError('"options.mandatoryPointers" is not allowed.', {
      name: 'NotAllowedError',
      details: {
        httpStatusCode: 400,
        public: true
      }
    });
  }
  const mandatoryPointers = cryptosuiteConfig?.options?.mandatoryPointers ??
    options?.mandatoryPointers ?? ['/issuer'];
  const cryptosuite = createEcdsaSd2023SignCryptosuite({
    mandatoryPointers
  });
  const diProof = new DataIntegrityProof({
    signer,
    date: _getCreated({cryptosuiteConfig}),
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
  const extraInformation = Buffer.from(options.extraInformation, 'base64url');
  const cryptosuite = createEcdsaXi2023SignCryptosuite({
    extraInformation
  });
  return new DataIntegrityProof({
    signer,
    date: null,
    cryptosuite
  });
}

async function _createBbs2023Suite({signer, options, cryptosuiteConfig} = {}) {
  // enforce `cryptosuiteConfig.options` if given
  if(cryptosuiteConfig?.options?.mandatoryPointers &&
    options?.mandatoryPointers) {
    throw new BedrockError('"options.mandatoryPointers" is not allowed.', {
      name: 'NotAllowedError',
      details: {
        httpStatusCode: 400,
        public: true
      }
    });
  }
  const mandatoryPointers = cryptosuiteConfig?.options?.mandatoryPointers ??
    options?.mandatoryPointers ?? ['/issuer'];

  // BBS requires signer public key
  const {publicKeyMultibase} = await signer.getKeyDescription();
  const {publicKey} = await Bls12381Multikey.from({publicKeyMultibase});
  signer.publicKey = publicKey;
  const cryptosuite = createBbs2023SignCryptosuite({
    mandatoryPointers
  });
  const diProof = new DataIntegrityProof({
    signer,
    date: _getCreated({cryptosuiteConfig}),
    cryptosuite
  });
  diProof.proof = {id: `urn:uuid:${uuid()}`};
  return diProof;
}

function _getCreated({cryptosuiteConfig, date = new Date()}) {
  if(cryptosuiteConfig.options?.includeCreated === true) {
    return _getISODateTime(date);
  }
  return null;
}

function _getISODateTime(date) {
  // remove milliseconds precision
  return date.toISOString().replace(/\.\d+Z$/, 'Z');
}

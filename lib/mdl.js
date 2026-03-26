/*!
 * Copyright (c) 2025-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  CoseKey, DeviceKey, Issuer as MDocIssuer, SignatureAlgorithm
} from '@owf/mdoc';
import {encode as cborEncode} from 'cborg';
import {compile} from '@bedrock/validation';
import {vDL} from '../schemas/bedrock-vc-issuer.js';
import {X509Certificate} from 'node:crypto';

const {util: {BedrockError}} = bedrock;

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const MDOC_TYPE_MDL = `${MDL_NAMESPACE}.mDL`;

const VALIDATORS = {
  vDL: null
};

bedrock.events.on('bedrock.init', () => {
  // create validators
  VALIDATORS.vDL = compile({schema: vDL()});
});

// produce mDL-enveloped VC
export async function envelopeCredential({
  verifiableCredential, signer, options = {}, envelopeConfig = {}
} = {}) {
  // `verifiableCredential` must be a vDL; this can be mapped to an mDL
  _validate(VALIDATORS.vDL, verifiableCredential);

  const {
    credentialSubject,
    validFrom = verifiableCredential.issuanceDate,
    validUntil = verifiableCredential.expirationDate
  } = verifiableCredential;

  // initialize validity info
  const validityInfo = {
    validFrom: validFrom ? new Date(validFrom) : undefined,
    validUntil: validFrom ? new Date(validUntil) : undefined
  };

  // get fields for mDL from vDL fields
  const fields = {...credentialSubject.driversLicense};
  delete fields.type;

  // parse issuer certificate chain and use it to modulate validity period
  const issuerCertificateChain = envelopeConfig
    .options?.issuerCertificateChain?.map(pem => {
      const certificate = new X509Certificate(pem);
      // limit validity period to certificate period
      if(validityInfo.validFrom < certificate.notBefore) {
        validityInfo.validFrom = certificate.notBefore;
      }
      if(validityInfo.validUntil > certificate.notAfter) {
        validityInfo.validUntil = certificate.notAfter;
      }
      return certificate.raw;
    });

  // ensure `signed` date is within validity period per request
  const now = new Date();
  if(now < validityInfo.validFrom || now > validityInfo.validUntil) {
    validityInfo.signed = validityInfo.validFrom;
  } else {
    validityInfo.signed = now;
  }

  // device public key must be provided via options
  const {devicePublicJwk} = options.mdl ?? {};

  // construct and sign mDL
  const mdocContext = _createMdocContext({signer});
  const mdocIssuer = new MDocIssuer(MDOC_TYPE_MDL, mdocContext);
  mdocIssuer.addIssuerNamespace(MDL_NAMESPACE, fields);
  const issuerSigned = await mdocIssuer.sign({
    // `signingKey` intentionally includes no key material, only type
    // information; `signer` API is used to provide signature via `mdocContext`
    signingKey: CoseKey.fromJwk({
      kid: signer.id,
      kty: 'EC',
      crv: 'P-256'
    }),
    certificates: issuerCertificateChain,
    algorithm: envelopeConfig.options?.alg === 'ES256' ?
      SignatureAlgorithm.ES256 : _curveToAlgorithm(signer.algorithm),
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: {deviceKey: DeviceKey.fromJwk(devicePublicJwk)},
    validityInfo
  });

  // create mdoc container with empty `issuerSigned` with the right Map
  // size -- it will be replaced with the proper `issuerSigned` thereafter
  const mdoc = new Map([
    ['version', '1.0'],
    ['documents', [
      new Map([
        ['docType', MDOC_TYPE_MDL],
        ['issuerSigned', new Map([['nameSpaces', []], ['issuerAuth', []]])]
      ])
    ]]
  ]);
  const encoded = new Uint8Array(Buffer.concat([
    // 68 bytes into the payload, replace with encoded `issuerSigned`; this
    // must be done because there is no API available to wrap the
    // `issuerSigned` document with an mdoc container that does not also
    // include a `deviceSigned` document
    cborEncode(mdoc).subarray(0, 68),
    issuerSigned.encode()
  ]));

  return encoded;
}

// constructs an "mdoc context" based on the given `signer` and that implements
// the other necessary `digest` and `random` functions
function _createMdocContext({signer}) {
  const crypto = globalThis.crypto;
  return {
    crypto: {
      async digest({digestAlgorithm, bytes}) {
        const digest = await crypto.subtle.digest(digestAlgorithm, bytes);
        return new Uint8Array(digest);
      },
      random(length) {
        return crypto.getRandomValues(new Uint8Array(length));
      }
    },
    cose: {
      sign1: {
        async sign(input) {
          const {toBeSigned} = input;
          return signer.sign({data: toBeSigned});
        }
      }
    }
  };
}

function _curveToAlgorithm(crv) {
  if(crv === 'P-256') {
    return SignatureAlgorithm.ES256;
  }
  throw new BedrockError(`Unsupported key curve "${crv}".`, {
    name: 'NotSupportedError',
    details: {
      httpStatusCode: 500,
      public: true
    }
  });
}

function _validate(validator, data) {
  const result = validator(data);
  if(!result.valid) {
    throw result.error;
  }
}

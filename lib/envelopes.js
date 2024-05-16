/*!
 * Copyright (c) 2019-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';

const SUPPORTED_FORMATS = new Map([
  ['VC-JWT', {
    createEnveloper: _createVCJWTEnveloper
  }]
]);

const {util: {BedrockError}} = bedrock;

export function getEnvelopeParams({config, envelope}) {
  const {format, zcapReferenceIds} = envelope;

  // get zcap to use to invoke assertion method key
  const referenceId = zcapReferenceIds.assertionMethod;
  const zcap = config.zcaps[referenceId];

  // ensure envelope is supported
  const envelopeInfo = SUPPORTED_FORMATS.get(format);
  if(!envelopeInfo) {
    throw new BedrockError(`Unsupported envelope format "${format}".`, {
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
      `No capability available to sign using envelope format "${format}".`, {
        name: 'DataError',
        details: {
          httpStatusCode: 500,
          public: true
        }
      });
  }

  const {createEnveloper} = envelopeInfo;
  return {zcap, createEnveloper, referenceId, envelope};
}

function _createVCJWTEnveloper() {//{signer, options} = {}) {
  // FIXME: `jws` / `jwt` options? claims? header?
  //const {alg} = options;
  // FIXME:
  //const date = _getISODateTime();
  return {
    // FIXME:
    async envelope() {//{verifiableCredential} = {}) {
      // FIXME:
      return {data: 'FIXME', mediaType: 'application/jwt'};
    }
  };
}
/*
function _getISODateTime(date = new Date()) {
  // remove milliseconds precision
  return date.toISOString().replace(/\.\d+Z$/, 'Z');
}
*/

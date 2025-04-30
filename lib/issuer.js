/*!
 * Copyright (c) 2020-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as vc from '@digitalbazaar/vc';
import {
  getDocumentStore, getIssuerAndSecuringMethods
} from './helpers.js';
import assert from 'assert-plus';
import {createDocumentLoader} from './documentLoader.js';
import {CredentialStatusIssuer} from './CredentialStatusIssuer.js';
import {CredentialStatusWriter} from './CredentialStatusWriter.js';
import jsonld from 'jsonld';
import {randomUUID as uuid} from 'node:crypto';
import {named as vcNamedContexts} from '@bedrock/credentials-context';

const {util: {BedrockError}} = bedrock;

const CREDENTIALS_CONTEXT_V2_URL = 'https://www.w3.org/ns/credentials/v2';

// exported for testing purposes
export const _CredentialStatusWriter = CredentialStatusWriter;

export async function issue({credential, config, options = {}} = {}) {
  assert.object(credential, 'credential');
  assert.object(config, 'config');
  assert.object(options, 'options');

  // see if config indicates a credential status should be set
  const {statusListOptions = []} = config;

  const [documentLoader, documentStore, issuerInfo] = await Promise.all([
    createDocumentLoader({config}),
    // only fetch `documentStore` if a status list is configured; otherwise,
    // it is not needed
    statusListOptions.length > 0 ? getDocumentStore({config}) : {},
    getIssuerAndSecuringMethods({config, options})
  ]);

  const {issuer, suites, enveloper} = issuerInfo;

  if(typeof credential.issuer === 'object') {
    credential.issuer = {
      ...credential.issuer,
      id: issuer
    };
  } else {
    credential.issuer = issuer;
  }

  // initialize `CredentialStatusIssuer` for handling any credential statuses
  let credentialStatusIssuer;
  const {edvClient} = documentStore;
  if(statusListOptions.length > 0) {
    credentialStatusIssuer = new CredentialStatusIssuer({
      config, documentLoader, edvClient
    });
    await credentialStatusIssuer.initialize({credential});
  }

  let issued = false;
  let verifiableCredential;
  let envelope;
  let envelopedVerifiableCredential;
  while(!issued) {
    // issue any credential status(es)
    const credentialStatus = await credentialStatusIssuer?.issue();

    // secure VC with any cryptosuites
    if(suites) {
      verifiableCredential = await _secureWithSuites({
        credential, documentLoader, suites
      });
    } else {
      verifiableCredential = credential;
    }

    // secure VC with any envelope
    if(enveloper) {
      // include issuance date in VC 1.x if not already present
      const contexts = Array.isArray(verifiableCredential['@context']) ?
        verifiableCredential['@context'] : [verifiableCredential['@context']];
      if(contexts.includes(vcNamedContexts.get('v1').id) &&
        verifiableCredential.issuanceDate === undefined) {
        verifiableCredential.issuanceDate = _getISODateTime();
      }
      ({envelope, envelopedVerifiableCredential} = await _secureWithEnvelope({
        verifiableCredential, enveloper
      }));
    }

    // if no credential status written, do not store VC; note that this means
    // that VC IDs will not be checked for duplicates, this will be the
    // responsibility of clients, etc.
    if(!(credentialStatus?.length > 0)) {
      issued = true;
      break;
    }

    // get `credentialId` for referring to this credential in the following
    // order of preference
    const credentialId = options.credentialId ?? credential.id ??
      `urn:uuid:${uuid()}`;

    try {
      // store issued VC, may throw on duplicate credential status(es) which
      // can be ignored and issuance can be reattempted with new status(es)
      const meta = {
        // include `meta.type` as a non-user input type to validate against
        type: 'VerifiableCredential',
        // include status meta for uniqueness checks and other info
        credentialStatus,
        // include credential reference ID
        credentialId
      };
      // add any envelope
      if(envelope) {
        meta.envelope = envelope;
      }
      await edvClient.insert({
        doc: {
          id: await edvClient.generateId(),
          content: verifiableCredential,
          meta
        }
      });
      issued = true;
    } catch(e) {
      if(e.name === 'DuplicateError') {
        // if duplicate error was caused by a duplicate credential `id` or
        // `credentialId`, it is non-recoverable, but caused by a duplicate
        // credential status, continue to try again
        const [
          duplicateIds, duplicateCredentialIds, duplicateStatus
        ] = await Promise.all([
          edvClient.count({equals: {'content.id': credential.id}}),
          edvClient.count({equals: {'meta.credentialId': credentialId}}),
          credentialStatusIssuer.hasDuplicate()
        ]);
        const duplicateCredentials = duplicateIds + duplicateCredentialIds;
        if(duplicateCredentials !== 0) {
          const details = {
            public: true,
            httpStatusCode: 409
          };
          if(duplicateIds !== 0) {
            details.duplicateId = credential.id;
          }
          if(duplicateCredentialIds !== 0 && credential.id !== credentialId) {
            details.duplicateCredentialId = credentialId;
          }
          throw new BedrockError(
            'Could not issue credential; duplicate credential ID.', {
              name: 'DuplicateError',
              details
            });
        }
        if(duplicateStatus) {
          // note: the `credentialStatusIssuer` will update IADs with
          // detected duplicates to resync so non-duplicate statuses will
          // eventually be assigned
          continue;
        }
      }

      // error not caused by a duplicate credential status, throw it
      throw e;
    }
  }

  // finish issuing status (non-async function and can safely fail)
  credentialStatusIssuer?.finish();

  return {verifiableCredential, envelope, envelopedVerifiableCredential};
}

async function _secureWithSuites({credential, documentLoader, suites}) {
  try {
    // vc-js.issue may be fixed to not mutate credential
    // see: https://github.com/digitalbazaar/vc-js/issues/76
    credential = {...credential};
    // validate JSON-LD for any JCS cryptosuites
    if(suites.some(s => s.cryptosuite?.includes('-jcs-'))) {
      await _validateJsonLd({document: credential, documentLoader});
    }
    // issue using each suite
    for(const suite of suites) {
      // update credential with latest proof(s)
      credential = await vc.issue({credential, documentLoader, suite});
    }
    // return credential with a proof for each suite
    return credential;
  } catch(e) {
    // throw 400 for JSON pointer related errors
    if(e.name === 'TypeError' && e.message?.includes('JSON pointer')) {
      throw new BedrockError(
        e.message, {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          },
          cause: e
        });
    }
    throw e;
  }
}

async function _secureWithEnvelope({verifiableCredential, enveloper}) {
  // envelope: {data, mediaType}
  const envelope = await enveloper.envelope({verifiableCredential});

  // encode bytes to base64 for both storage and Data URL
  if(envelope.data instanceof Uint8Array) {
    envelope.data = Buffer.from(envelope.data).toString('base64');
    envelope.encoding = 'base64';
  }
  const {data, mediaType, encoding} = envelope;
  const dataURL = `data:${mediaType}${encoding ? ';base64,' : ','}${data}`;

  const envelopedVerifiableCredential = {
    '@context': CREDENTIALS_CONTEXT_V2_URL,
    id: dataURL,
    type: 'EnvelopedVerifiableCredential'
  };
  return {envelope, envelopedVerifiableCredential};
}

function _getISODateTime(date = new Date()) {
  // remove milliseconds precision
  return date.toISOString().replace(/\.\d+Z$/, 'Z');
}

async function _validateJsonLd({document, documentLoader}) {
  // convert to RDF dataset
  const options = {
    base: null,
    safe: true,
    rdfDirection: 'i18n-datatype',
    produceGeneralizedRdf: false,
    documentLoader
  };
  await jsonld.toRDF(document, options);
}

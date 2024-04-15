/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  issue as _issue,
  getDocumentStore, getIssuerAndSuites
} from './helpers.js';
import assert from 'assert-plus';
import {createDocumentLoader} from './documentLoader.js';
import {CredentialStatusIssuer} from './CredentialStatusIssuer.js';
import {CredentialStatusWriter} from './CredentialStatusWriter.js';
import {v4 as uuid} from 'uuid';

const {util: {BedrockError}} = bedrock;

// exported for testing purposes
export const _CredentialStatusWriter = CredentialStatusWriter;

export async function issue({credential, config, options = {}} = {}) {
  assert.object(credential, 'credential');
  assert.object(config, 'config');
  assert.object(options, 'options');

  // see if config indicates a credential status should be set
  const {statusListOptions = []} = config;

  const [documentLoader, documentStore, {issuer, suites}] = await Promise.all([
    createDocumentLoader({config}),
    // only fetch `documentStore` if a status list is configured; otherwise,
    // it is not needed
    statusListOptions.length > 0 ? getDocumentStore({config}) : {},
    getIssuerAndSuites({config, options})
  ]);

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
  while(!issued) {
    // issue any credential status(es)
    const credentialStatus = await credentialStatusIssuer?.issue();

    // issue VC
    verifiableCredential = await _issue({credential, documentLoader, suites});

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
      await edvClient.insert({
        doc: {
          id: await edvClient.generateId(),
          content: verifiableCredential,
          meta: {
            // include `meta.type` as a non-user input type to validate against
            type: 'VerifiableCredential',
            // include status meta for uniqueness checks and other info
            credentialStatus,
            // include credential reference ID
            credentialId
          }
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

  return verifiableCredential;
}

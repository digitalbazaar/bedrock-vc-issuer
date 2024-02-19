/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  issue as _issue,
  getDocumentStore, getIssuerAndSuite
} from './helpers.js';
import assert from 'assert-plus';
import {createDocumentLoader} from './documentLoader.js';
import {CredentialStatusIssuer} from './CredentialStatusIssuer.js';
import {CredentialStatusWriter} from './CredentialStatusWriter.js';

const {util: {BedrockError}} = bedrock;

// exported for testing purposes
export const _CredentialStatusWriter = CredentialStatusWriter;

export async function issue({credential, config} = {}) {
  assert.object(credential, 'credential');
  assert.object(config, 'config');

  // see if config indicates a credential status should be set
  const {statusListOptions = []} = config;

  const {suiteName} = config.issueOptions;
  const [documentLoader, documentStore, {issuer, suite}] = await Promise.all([
    createDocumentLoader({config}),
    // only fetch `documentStore` if a status list is configured; otherwise,
    // it is not needed
    statusListOptions.length > 0 ? getDocumentStore({config}) : {},
    getIssuerAndSuite({config, suiteName})
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
    console.log('issue VC with status', credential.credentialStatus);
    verifiableCredential = await _issue({credential, documentLoader, suite});

    // if no credential status written, do not store VC; note that this means
    // that VC IDs will not be checked for duplicates, this will be the
    // responsibility of clients, etc.
    if(!(credentialStatus?.length > 0)) {
      issued = true;
      break;
    }

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
            credentialStatus
          }
        }
      });
      issued = true;
    } catch(e) {
      if(e.name === 'DuplicateError') {
        // if duplicate error was caused by a duplicate credential ID, it is
        // non-recoverable, but caused by a duplicate credential status,
        // continue to try again
        const [duplicateCredentials, duplicateStatus] = await Promise.all([
          edvClient.count({equals: {'content.id': credential.id}}),
          credentialStatusIssuer.hasDuplicate()
        ]);
        if(duplicateCredentials !== 0) {
          throw new BedrockError(
            'Could not issue credential; duplicate credential ID.',
            'DuplicateError', {
              public: true,
              httpStatusCode: 409
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

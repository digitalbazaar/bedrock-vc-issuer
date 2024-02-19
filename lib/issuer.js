/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  issue as _issue,
  assertSlcDoc,
  getDocumentStore, getIssuerAndSuite
} from './helpers.js';
import assert from 'assert-plus';
import {createDocumentLoader} from './documentLoader.js';
import {CredentialStatusIssuer} from './CredentialStatusIssuer.js';
import {CredentialStatusWriter} from './CredentialStatusWriter.js';
import {decodeList} from '@digitalbazaar/vc-status-list';

const {util: {BedrockError}} = bedrock;

// exported for testing purposes
export const _CredentialStatusWriter = CredentialStatusWriter;

export async function issue({credential, config, options} = {}) {
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
    getIssuerAndSuite({config, suiteName, options})
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

// FIXME: move to `slcs.js`
// FIXME: call out to status service
export async function setStatus({id, config, credentialStatus, status} = {}) {
  assert.string(id, 'id');
  assert.object(config, 'config');
  assert.object(credentialStatus, 'credentialStatus');
  assert.bool(status, 'status');

  const [documentLoader, documentStore] = await Promise.all([
    createDocumentLoader({config}),
    getDocumentStore({config})
  ]);

  // check `credentialStatus` against credential meta information
  const {meta} = await documentStore.get({id});
  const {
    statusListCredential, statusListIndex
  } = getMatchingStatusListCredentialMeta({
    meta, credentialStatus
  });

  // get SLC document; do not use cache to ensure latest doc is retrieved
  let slcDoc = await documentStore.get(
    {id: statusListCredential, useCache: false});
  assertSlcDoc({slcDoc, id: statusListCredential});

  // TODO: use `documentStore.upsert` and `mutator` feature
  const {edvClient} = documentStore;

  while(true) {
    try {
      // check if `credential` status is already set, if so, done
      const slc = slcDoc.content;
      const {credentialSubject: {encodedList}} = slc;
      const list = await decodeList({encodedList});
      if(list.getStatus(statusListIndex) === status) {
        return;
      }

      // update issuer
      const {meta: {statusListConfig}} = slcDoc;
      const {issuer, suite} = await getIssuerAndSuite({
        config, suiteName: statusListConfig.suiteName
      });
      slc.issuer = issuer;

      // use index to set status
      list.setStatus(statusListIndex, status);
      slc.credentialSubject.encodedList = await list.encode();

      // express date without milliseconds
      const date = new Date();
      // TODO: use `validFrom` and `validUntil` for v2 VCs
      slc.issuanceDate = `${date.toISOString().slice(0, -5)}Z`;
      // FIXME: get validity period via status service instance config
      date.setDate(date.getDate() + 1);
      slc.expirationDate = `${date.toISOString().slice(0, -5)}Z`;
      // delete existing proof and reissue SLC VC
      delete slc.proof;
      slcDoc.content = await _issue({credential: slc, documentLoader, suite});

      // update SLC doc
      await edvClient.update({doc: slcDoc});
      return;
    } catch(e) {
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
      // ignore conflict, read and try again
      slcDoc = await edvClient.get({id: slcDoc.id});
    }
  }
}

export function getMatchingStatusListCredentialMeta({
  meta, credentialStatus
} = {}) {
  // return match against `meta.credentialStatus` where the status entry
  // type and status purpose match
  const candidates = meta.credentialStatus || [];
  for(const c of candidates) {
    if(c.type === credentialStatus.type &&
      (credentialStatus.type === 'RevocationList2020Status' ||
      c.statusPurpose === credentialStatus.statusPurpose)) {
      return c;
    }
  }

  let purposeMessage = '';
  if(credentialStatus.statusPurpose) {
    purposeMessage =
      `with status purpose "${credentialStatus.statusPurpose}" `;
  }

  throw new BedrockError(
    `Credential status type "${credentialStatus.type}" ${purposeMessage}` +
    'is not supported by this issuer instance.', 'NotSupportedError', {
      httpStatusCode: 400,
      public: true
    });
}

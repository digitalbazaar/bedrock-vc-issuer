/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as slcs from './slcs.js';
import {
  issue as _issue, getCredentialStatusInfo, getIssuerAndSuite
} from './helpers.js';
import assert from 'assert-plus';
import {createDocumentLoader} from './documentLoader.js';
import {CredentialStatusIssuer} from './CredentialStatusIssuer.js';
import {CredentialStatusWriter} from './CredentialStatusWriter.js';
import {decodeList} from '@digitalbazaar/vc-status-list';
import {documentStores} from '@bedrock/service-agent';
import {serviceType} from './constants.js';

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
    statusListOptions.length > 0 ? _getDocumentStore({config}) : {},
    getIssuerAndSuite({config, suiteName, options})
  ]);
  const {edvClient} = documentStore;

  if(typeof credential.issuer === 'object') {
    credential.issuer = {
      ...credential.issuer,
      id: issuer
    };
  } else {
    credential.issuer = issuer;
  }

  // initialize `CredentialStatusIssuer` for handling any credential statuses
  const credentialStatusIssuer = new CredentialStatusIssuer({
    config, documentLoader, edvClient
  });
  await credentialStatusIssuer.initialize({credential});

  let issued = false;
  let verifiableCredential;
  while(!issued) {
    // issue any credential status(es)
    const credentialStatus = await credentialStatusIssuer.issue();

    // issue VC
    console.log('issue VC with status', credential.credentialStatus);
    verifiableCredential = await _issue({credential, documentLoader, suite});

    // if no credential status written, do not store VC; note that this means
    // that VC IDs will not be checked for duplicates, this will be the
    // responsibility of clients, etc.
    if(credentialStatus.length === 0) {
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
        // non-recoverable
        if(await edvClient.count({
          equals: {'content.id': credential.id}
        }) !== 0) {
          throw new BedrockError(
            'Could not issue credential; duplicate credential ID.',
            'DuplicateError', {
              public: true,
              httpStatusCode: 409
            });
        }

        // if caused by a duplicate credential status, continue to try again
        if(await credentialStatusIssuer.hasDuplicate()) {
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
  credentialStatusIssuer.finish();

  return verifiableCredential;
}

export async function publishSlc({id, config} = {}) {
  assert.string(id, 'id');
  assert.object(config, 'config');

  // do not use cache to ensure latest doc is published
  const documentStore = await _getDocumentStore({config});
  const slcDoc = await documentStore.get({id, useCache: false});
  const {content: credential, meta, sequence} = slcDoc;
  if(!(meta.type === 'VerifiableCredential' &&
    _isStatusListCredential({credential}))) {
    throw new BedrockError(
      `Credential "${id}" is not a supported status list credential.`,
      'DataError', {
        httpStatusCode: 400,
        public: true
      });
  }
  try {
    // store SLC Doc for public serving
    await slcs.set({credential, sequence});
  } catch(e) {
    // safe to ignore conflicts, a newer version of the SLC was published
    // than the one that was retrieved
    if(e.name === 'InvalidStateError' || e.name === 'DuplicateError') {
      return;
    }
    throw e;
  }
}

export async function setStatus({id, config, statusListConfig, status} = {}) {
  assert.string(id, 'id');
  assert.object(config, 'config');
  assert.object(statusListConfig, 'statusListConfig');
  assert.bool(status, 'status');

  const [
    documentLoader,
    documentStore,
    {issuer, suite}
  ] = await Promise.all([
    createDocumentLoader({config}),
    _getDocumentStore({config}),
    getIssuerAndSuite({config, suiteName: statusListConfig.suiteName})
  ]);

  // get credential
  const {content: credential} = await documentStore.get({id});

  // get SLC document
  const {
    statusListIndex, statusListCredential
  } = getCredentialStatusInfo({credential, statusListConfig});

  // do not use cache to ensure latest doc is retrieved
  let slcDoc = await documentStore.get(
    {id: statusListCredential, useCache: false});

  // TODO: use `documentStore.upsert` and `mutator` feature
  const {edvClient} = documentStore;

  let slcId;
  let slcUpdated = false;
  while(!slcUpdated) {
    try {
      // check if `credential` status is already set, if so, done
      const slc = slcDoc.content;
      const {credentialSubject: {encodedList}} = slc;
      slcId = slc.id;
      const list = await decodeList({encodedList});
      if(list.getStatus(statusListIndex) === status) {
        slcUpdated = true;
        break;
      }

      // update issuer
      slc.issuer = issuer;

      // use index to set status
      list.setStatus(statusListIndex, status);
      slc.credentialSubject.encodedList = await list.encode();

      // express date without milliseconds
      const now = (new Date()).toJSON();
      slc.issuanceDate = `${now.slice(0, -5)}Z`;
      // TODO: we want to be using `issued` and/or `validFrom`, right?
      //slc.issued = issuanceDate;

      // delete existing proof and reissue SLC VC
      delete slc.proof;
      slcDoc.content = await _issue({credential: slc, documentLoader, suite});

      // update SLC doc
      await edvClient.update({doc: slcDoc});
      slcUpdated = true;
    } catch(e) {
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
      // ignore conflict, read and try again
      slcDoc = await edvClient.get({id: slcDoc.id});
    }
  }

  // publish latest version of SLC for non-authz consumption
  await publishSlc({id: slcId, config});
}

export function getMatchingStatusListConfig({config, credentialStatus} = {}) {
  // FIXME: use helper functions from `vc-revocation-list`/`vc-status-list`
  // once they allow context checks to be skipped?
  const {statusListOptions = []} = config;
  for(const statusListConfig of statusListOptions) {
    // default `type` is `RevocationList2020`
    const {type = 'RevocationList2020', statusPurpose} = statusListConfig;
    if(type === 'RevocationList2020' &&
      credentialStatus.type === 'RevocationList2020Status') {
      return {type, ...statusListConfig};
    }
    if(type === 'StatusList2021' &&
      credentialStatus.type === 'StatusList2021Entry' &&
      credentialStatus.statusPurpose === statusPurpose) {
      return statusListConfig;
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

async function _getDocumentStore({config}) {
  // ensure indexes are set for VCs
  const {documentStore} = await documentStores.get({config, serviceType});
  const {edvClient} = documentStore;
  // use `meta.credentialStatus.id` field as some credentials may not include
  // the ID directly
  edvClient.ensureIndex({
    attribute: ['meta.credentialStatus.id'],
    unique: true
  });
  return documentStore;
}

// check if `credential` is some known type of status list credential
function _isStatusListCredential({credential}) {
  // FIXME: check for VC context as well
  if(!(credential['@context'] && Array.isArray(credential['@context']))) {
    return false;
  }
  if(!(credential.type && Array.isArray(credential.type) &&
    credential.type.includes('VerifiableCredential'))) {
    return false;
  }

  for(const type of credential.type) {
    if(type === 'RevocationList2020Credential') {
      // FIXME: check for matching `@context` as well
      return true;
    }
    if(type === 'StatusList2021Credential') {
      // FIXME: check for matching `@context as well
      return true;
    }
  }
  // FIXME: check other types

  return false;
}

/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';
import {
  assertSlcDoc, getDocumentStore, getIssuerAndSuite, issue
} from './helpers.js';
import assert from 'assert-plus';
import {createDocumentLoader} from './documentLoader.js';
import {decodeList} from '@digitalbazaar/vc-status-list';
import {LruCache} from '@digitalbazaar/lru-memoize';

const {util: {BedrockError}} = bedrock;

const COLLECTION_NAME = 'vc-issuer-publishedSlc';
let SLC_CACHE;

bedrock.events.on('bedrock.init', () => {
  const cfg = bedrock.config['vc-issuer'];
  SLC_CACHE = new LruCache(cfg.caches.slc);
});

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await database.openCollections([COLLECTION_NAME]);

  await database.createIndexes([{
    collection: COLLECTION_NAME,
    fields: {'credential.id': 1},
    options: {unique: true, background: false}
  }]);
});

/**
 * Sets the published credential for the given status list credential ID
 * if the credential's `sequence` is after the one associated with the
 * currently stored credential (or if there is no currently stored credential).
 *
 * Note: This is the credential will be served when the ID endpoint is hit.
 *
 * @param {object} options - The options to use.
 * @param {string} options.credential - The credential.
 * @param {number} options.sequence - The sequence number associated with the
 *   credential; used to ensure only newer versions of the credential are
 *   stored.
 *
 * @returns {Promise<object>} Settles once the operation completes.
 */
export async function set({credential, sequence} = {}) {
  assert.object(credential, 'credential');

  try {
    const collection = database.collections[COLLECTION_NAME];
    const now = Date.now();
    const $set = {credential, 'meta.updated': now, 'meta.sequence': sequence};
    const result = await collection.updateOne({
      'credential.id': credential.id,
      'meta.sequence': {$lt: sequence}
    }, {
      $set,
      $setOnInsert: {'meta.created': now}
    }, {...database.writeOptions, upsert: true});

    if(result.result.n > 0) {
      // document upserted or modified: success; clear cache
      SLC_CACHE.delete(credential.id);
      return true;
    }
  } catch(e) {
    if(!database.isDuplicateError(e)) {
      throw e;
    }
    throw new BedrockError(
      'Duplicate status list credential.',
      'DuplicateError', {
        public: true,
        httpStatusCode: 409
      }, e);
  }

  throw new BedrockError(
    'Could not update status list credential. Sequence is stale.',
    'InvalidStateError', {
      httpStatusCode: 409,
      public: true,
      sequence
    });
}

/**
 * Gets the published credential for the given status list credential ID.
 * This is the credential to be served when the ID endpoint is hit.
 *
 * @param {object} options - The options to use.
 * @param {string} options.id - The ID of the status list credential.
 *
 * @returns {Promise<object>} Resolves to the stored record.
 */
export async function get({id} = {}) {
  assert.string(id, 'id');

  // use cache
  const fn = () => _getUncachedRecord({id});
  return SLC_CACHE.memoize({key: id, fn});
}

/**
 * Returns true if a status list credential has been stored and false if not.
 *
 * @param {object} options - The options to use.
 * @param {string} options.id - The ID of the status list credential.
 *
 * @returns {Promise<boolean>} Resolves to true if stored, false if not.
 */
export async function exists({id}) {
  assert.string(id, 'id');
  const collection = database.collections[COLLECTION_NAME];
  const record = await collection.findOne(
    {'credential.id': id}, {projection: {_id: 0, id: 1}});
  return !!record;
}

/**
 * Publishes the status list credential with the given ID for the given
 * issuer `config` -- if a newer version (since the time at which this function
 * was called) has not already been published.
 *
 * @param {object} options - The options to use.
 * @param {string} options.id - The SLC ID.
 * @param {object} options.config - The issuer config.
 *
 * @returns {Promise<object>} Settles once the operation completes.
 */
export async function publish({id, config} = {}) {
  assert.string(id, 'id');
  assert.object(config, 'config');

  // do not use cache to ensure latest doc is published
  // FIXME: pass `documentStore` instead?
  const documentStore = await getDocumentStore({config});
  const slcDoc = await documentStore.get({id, useCache: false});
  assertSlcDoc({slcDoc, id});
  const {content: credential, sequence} = slcDoc;
  try {
    // store SLC Doc for public serving
    await set({credential, sequence});
  } catch(e) {
    // safe to ignore conflicts, a newer version of the SLC was published
    // than the one that was retrieved
    if(e.name === 'InvalidStateError' || e.name === 'DuplicateError') {
      return;
    }
    throw e;
  }
}

export async function refresh({id, config} = {}) {
  assert.string(id, 'id');
  assert.object(config, 'config');

  // FIXME: pass `documentStore` instead?
  const [documentLoader, documentStore] = await Promise.all([
    createDocumentLoader({config}),
    getDocumentStore({config})
  ]);

  // do not use cache to ensure latest doc is retrieved
  let slcDoc = await documentStore.get({id, useCache: false});
  assertSlcDoc({slcDoc, id});

  // TODO: use `documentStore.upsert` and `mutator` feature
  const {edvClient} = documentStore;
  while(true) {
    try {
      // update issuer
      const slc = slcDoc.content;
      const {meta: {statusListConfig}} = slcDoc;
      const {issuer, suite} = await getIssuerAndSuite({
        config, suiteName: statusListConfig.suiteName
      });
      slc.issuer = issuer;

      // express current date without milliseconds
      const date = new Date();
      // TODO: use `validFrom` and `validUntil` for v2 VCs
      slc.issuanceDate = `${date.toISOString().slice(0, -5)}Z`;
      // FIXME: get validity period via status service instance config
      date.setDate(date.getDate() + 1);
      slc.expirationDate = `${date.toISOString().slice(0, -5)}Z`;
      // delete existing proof and reissue SLC VC
      delete slc.proof;
      slcDoc.content = await issue({credential: slc, documentLoader, suite});

      // update SLC doc
      slcDoc = await edvClient.update({doc: slcDoc});
      return slcDoc;
    } catch(e) {
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
      // ignore conflict, read and try again
      slcDoc = await edvClient.get({id: slcDoc.id});
    }
  }
}

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
  } = _getMatchingStatusListCredentialMeta({
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
      slcDoc.content = await issue({credential: slc, documentLoader, suite});

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

export function _getMatchingStatusListCredentialMeta({
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

async function _getUncachedRecord({id}) {
  const collection = database.collections[COLLECTION_NAME];
  const record = await collection.findOne(
    {'credential.id': id}, {projection: {_id: 0, credential: 1, meta: 1}});
  if(!record) {
    throw new BedrockError(
      'Status list credential not found.',
      'NotFoundError', {
        statusListCredential: id,
        httpStatusCode: 404,
        public: true
      });
  }
  return record;
}

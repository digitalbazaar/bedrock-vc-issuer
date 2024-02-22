/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';
import assert from 'assert-plus';
import {getDocumentStore} from './helpers.js';
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
  const documentStore = await getDocumentStore({config});
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

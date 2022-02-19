/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import bedrock from 'bedrock';
import database from 'bedrock-mongodb';
const {util: {BedrockError}} = bedrock;

const COLLECTION_NAME = 'vc-issuer-publishedSlc';

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await database.openCollections([COLLECTION_NAME]);

  await database.createIndexes([{
    collection: COLLECTION_NAME,
    fields: {'credential.id': 1},
    options: {unique: true, background: false}
  }]);
});

/**
 * Sets the published credential for the given RevocationListCredential ID
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

  const now = Date.now();

  try {
    const collection = database.collections[COLLECTION_NAME];
    const $set = {credential, 'meta.updated': now, 'meta.sequence': sequence};
    const result = await collection.updateOne({
      'credential.id': credential.id,
      'meta.sequence': {$lt: sequence}
    }, {
      $set,
      $setOnInsert: {'meta.created': now}
    }, {...database.writeOptions, upsert: true});

    if(result.result.n > 0) {
      // document upserted or modified: success
      return true;
    }
  } catch(e) {
    if(!database.isDuplicateError(e)) {
      throw e;
    }
    throw new BedrockError(
      'Duplicate revocation list credential.',
      'DuplicateError', {
        public: true,
        httpStatusCode: 409
      }, e);
  }

  throw new BedrockError(
    'Could not update revocation list credential. Sequence is stale.',
    'InvalidStateError', {
      httpStatusCode: 409,
      public: true,
      sequence
    });
}

/**
 * Gets the published credential for the given RevocationListCredential ID.
 * This is the credential to be served when the ID endpoint is hit.
 *
 * @param {object} options - The options to use.
 * @param {string} options.id - The ID of the RevocationListCredential.
 *
 * @returns {Promise<object>} Resolves to the stored record.
 */
export async function get({id} = {}) {
  assert.string(id, 'id');
  const collection = database.collections[COLLECTION_NAME];
  const record = await collection.findOne(
    {'credential.id': id}, {projection: {_id: 0, credential: 1, meta: 1}});
  if(!record) {
    throw new BedrockError(
      'Revocation list credential not found.',
      'NotFoundError', {
        revocationListCredential: id,
        httpStatusCode: 404,
        public: true
      });
  }
  return record;
}

/**
 * Returns true if a RevocationListCredential has been stored and false if not.
 *
 * @param {object} options - The options to use.
 * @param {string} options.id - The ID of the RevocationListCredential.
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

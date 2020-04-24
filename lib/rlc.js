/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const assert = require('assert-plus');
const bedrock = require('bedrock');
const database = require('bedrock-mongodb');
const {promisify} = require('util');
const {util: {BedrockError}} = require('bedrock');

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await promisify(database.openCollections)(['vc-issuer-publishedRlc']);

  await promisify(database.createIndexes)([{
    collection: 'vc-issuer-publishedRlc',
    fields: {id: 1},
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
 * @param {string} credential - The credential.
 * @param {number} sequence - The sequence number associated with the
 *   credential; used to ensure only newer versions of the credential are
 *   stored.
 *
 * @return {Promise<Object>} resolves once the operation completes.
 */
exports.set = async ({credential, sequence}) => {
  assert.object(credential, 'credential');

  const now = Date.now();
  const meta = {
    created: now,
    updated: now,
    sequence
  };
  const record = {
    id: database.hash(credential.id),
    meta,
    credential
  };

  try {
    const collection = database.collections['vc-issuer-publishedRlc'];
    const $set = {credential, 'meta.updated': now, 'meta.sequence': sequence};
    const result = await collection.update({
      id: record.id,
      'meta.sequence': {$lt: sequence}
    }, {
      $set,
      $setOnInsert: {id: record.id, 'meta.created': now}
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
};

/**
 * Gets the published credential for the given RevocationListCredential ID.
 * This is the credential to be served when the ID endpoint is hit.
 *
 * @param {string} id - The ID of the RevocationListCredential.
 *
 * @return {Promise<Object>} resolves to the stored record.
 */
exports.get = async ({id}) => {
  assert.string(id, 'id');
  const collection = database.collections['vc-issuer-publishedRlc'];
  const record = await collection.findOne(
    {id: database.hash(id)}, {_id: 0, credential: 1, meta: 1});
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
};

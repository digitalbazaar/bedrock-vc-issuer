/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const database = require('bedrock-mongodb');
const {promisify} = require('util');
const {util: {BedrockError}} = bedrock;

// load config defaults
require('./config');

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await promisify(database.openCollections)(['vcIssuerInstance']);

  await promisify(database.createIndexes)([{
    // cover queries by issuer; unique (one instance per issuer)
    collection: 'vcIssuerInstance',
    fields: {issuer: 1},
    options: {unique: true, background: false}
  }, {
    // cover queries by controller; not unique
    collection: 'vcIssuerInstance',
    fields: {controller: 1},
    options: {unique: false, background: false}
  }]);
});

exports.create = async ({instance}) => {
  // insert the instance and get the updated record
  const now = Date.now();
  const meta = {created: now, updated: now};
  let record = {
    controller: database.hash(instance.controller),
    issuer: database.hash(instance.issuer),
    meta,
    instance
  };
  try {
    const result = await database.collections.vcIssuerInstance.insert(
      record, database.writeOptions);
    record = result.ops[0];
  } catch(e) {
    if(!database.isDuplicateError(e)) {
      throw e;
    }
    throw new BedrockError(
      'Duplicate issuer instance.',
      'DuplicateError', {
        public: true,
        httpStatusCode: 409
      }, e);
  }
  return record;
};

// get a particular instance
exports.get = async ({issuer}) => {
  const record = await database.collections.vcIssuerInstance.findOne(
    {issuer: database.hash(issuer)}, {_id: 0, instance: 1});
  if(!record) {
    throw new BedrockError(
      'Issuer instance not found.',
      'NotFoundError',
      {issuer, httpStatusCode: 404, public: true});
  }
  return record;
};

// get all issuer instances (optionally filtered by controller)
exports.getAll = async ({controller} = {}) => {
  const query = {};
  if(controller) {
    query.controller = database.hash(controller);
  }
  const records = await database.collections.vcIssuerInstance.find(query)
    .toArray();
  return records;
};

// remove an issuer instance
exports.remove = async ({issuer}) => {
  const query = {issuer: database.hash(issuer)};
  const result = await database.collections.vcIssuerInstance.remove(query);
  return result.result.n !== 0;
};

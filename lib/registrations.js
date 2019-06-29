/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const database = require('bedrock-mongodb');
const {promisify} = require('util');
const {util: {BedrockError}} = bedrock;

// load config defaults
require('./config');

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await promisify(database.openCollections)(['vcIssuerRegistration']);

  await promisify(database.createIndexes)([{
    // cover queries by issuer; unique (one registration per issuer)
    collection: 'vcIssuerRegistration',
    fields: {issuer: 1},
    options: {unique: true, background: false}
  }, {
    // cover queries by controller; not unique
    collection: 'vcIssuerRegistration',
    fields: {controller: 1},
    options: {unique: false, background: false}
  }]);
});

exports.create = async ({registration}) => {
  // insert the registration and get the updated record
  const now = Date.now();
  const meta = {created: now, updated: now};
  let record = {
    controller: database.hash(registration.controller),
    issuer: database.hash(registration.issuer),
    meta,
    registration
  };
  try {
    const result = await database.collections.vcIssuerRegistration.insert(
      record, database.writeOptions);
    record = result.ops[0];
  } catch(e) {
    if(!database.isDuplicateError(e)) {
      throw e;
    }
    throw new BedrockError(
      'Duplicate issuer registration.',
      'DuplicateError', {
        public: true,
        httpStatusCode: 409
      }, e);
  }
  return record;
};

// get a particular registration
exports.get = async ({issuer}) => {
  const record = await database.collections.vcIssuerRegistration.findOne(
    {issuer: database.hash(issuer)}, {_id: 0, registration: 1});
  if(!record) {
    throw new BedrockError(
      'Issuer registration not found.',
      'NotFoundError',
      {issuer, httpStatusCode: 404, public: true});
  }
  return record;
};

// get all issuer registrations (optionally filtered by controller)
exports.getAll = async ({controller} = {}) => {
  const query = {};
  if(controller) {
    query.controller = database.hash(controller);
  }
  const records = await database.collections.vcIssuerRegistration.find(query)
    .toArray();
  return records;
};

// remove an issuer registration
exports.remove = async ({issuer}) => {
  const query = {issuer: database.hash(issuer)};
  const result = await database.collections.vcIssuerRegistration.remove(query);
  return result.result.n !== 0;
};

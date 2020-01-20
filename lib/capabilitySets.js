/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const assert = require('assert-plus');
const bedrock = require('bedrock');
const database = require('bedrock-mongodb');
const {promisify} = require('util');
const {util: {BedrockError}} = bedrock;
const {revokeCapabilities} = require('./zcaps');
const instances = require('./instances');

// load config defaults
require('./config');

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await promisify(database.openCollections)(['vcIssuerCapabilitySet']);

  await promisify(database.createIndexes)([{
    // cover capability set queries by instance ID + user ID
    collection: 'vcIssuerCapabilitySet',
    fields: {'capabilitySet.instance': 1, 'capabilitySet.user': 1},
    options: {unique: true, background: false}
  }, {
    // cover capability set queries by instance ID + account ID
    collection: 'vcIssuerCapabilitySet',
    fields: {account: 1, 'capabilitySet.instance': 1},
    options: {
      partialFilterExpression: {account: {$exists: true}},
      unique: true,
      background: false
    }
  }]);
});

// create a capability set
exports.create = async ({capabilitySet}) => {
  assertCapabilitySet(capabilitySet);
  if(capabilitySet.sequence !== 0) {
    throw new BedrockError(
      'Issuer instance capability set sequence must be zero when created.',
      'InvalidStateError', {
        public: true,
        httpStatusCode: 400
      });
  }

  // insert the capability set and get the updated record
  const now = Date.now();
  const meta = {created: now, updated: now};
  let record = {
    meta,
    capabilitySet
  };
  try {
    const result = await database.collections.vcIssuerCapabilitySet.insert(
      record, database.writeOptions);
    record = result.ops[0];
  } catch(e) {
    if(!database.isDuplicateError(e)) {
      throw e;
    }
    throw new BedrockError(
      'Duplicate issuer instance capability set.',
      'DuplicateError', {
        public: true,
        httpStatusCode: 409
      }, e);
  }
  return record;
};

// get a capability set by instance ID and user ID
exports.get = async ({instanceId, userId, accountId}) => {
  assert.string(instanceId, 'instanceId');
  assert.optionalString(userId, 'userId');
  assert.optionalString(accountId, 'accountId');
  if(!userId && !accountId) {
    throw new TypeError('"userId" or "accountId" must be given.');
  }

  const query = {'capabilitySet.instance': instanceId};
  if(accountId) {
    query.account = database.hash(accountId);
  }
  if(userId) {
    query['capabilitySet.user'] = userId;
  }
  const record = await database.collections.vcIssuerCapabilitySet.findOne(
    query, {_id: 0, capabilitySet: 1, meta: 1});
  if(!record) {
    const details = {instance: instanceId, httpStatusCode: 404, public: true};
    if(accountId) {
      details.account = accountId;
    }
    if(userId) {
      details.user = userId;
    }
    throw new BedrockError(
      'Issuer instance capability set not found.',
      'NotFoundError', details);
  }
  return record;
};

// get all capability sets (optionally for an account or for an instance)
exports.getAll = async ({accountId, instanceId} = {}) => {
  assert.optionalString('accountId', accountId);
  assert.optionalString('instanceId', instanceId);

  const query = {};
  if(accountId) {
    query.account = database.hash(accountId);
  } else if(instanceId) {
    query['capabilitySet.instance'] = instanceId;
  }
  const records = await database.collections.vcIssuerCapabilitySet.find(
    query, {_id: 0, capabilitySet: 1, meta: 1}).toArray();
  return records;
};

// update capability set
exports.update = async ({capabilitySet}) => {
  assertCapabilitySet(capabilitySet);

  // get existing capability set
  const {instance: instanceId} = capabilitySet;
  const oldRecord = await exports.get({
    instanceId,
    userId: capabilitySet.user
  });

  // ensure sequence number for old set is one less than new set
  const {capabilitySet: oldSet} = oldRecord;
  const expectedSequence = oldSet.sequence + 1;
  if(capabilitySet.sequence !== expectedSequence) {
    throw new BedrockError(
      'Could not update issuer instance capability set; ' +
      'unexpected sequence number.',
      'InvalidStateError', {
        public: true,
        httpStatusCode: 409,
        actual: capabilitySet.sequence,
        expected: expectedSequence
      });
  }

  // determine which zcaps must be revoked
  const zcapsToRevoke = getZcapsToRevoke({oldSet, newSet: capabilitySet});

  // revoke old zcaps
  const instance = await instances.get({id: instanceId});
  const controllerKey = await instances.getControllerKey({id: instanceId});
  await revokeCapabilities({instance, controllerKey, zcaps: zcapsToRevoke});

  // update record
  const query = {
    'capabilitySet.instance': instanceId,
    'capabilitySet.user': capabilitySet.user,
    'capabilitySet.sequence': capabilitySet.sequence
  };
  const $set = {
    'meta.updated': Date.now(),
    capabilitySet
  };
  if(capabilitySet.account) {
    $set.account = database.hash(capabilitySet.account);
  }
  const result = await database.collections.vcIssuerInstance.update(
    query, {$set}, database.writeOptions);
  if(result.result.n === 0) {
    const details = {
      instance: instanceId,
      user: capabilitySet.user,
      httpStatusCode: 400,
      public: true
    };
    if(capabilitySet.account) {
      details.account = capabilitySet.account;
    }
    throw new BedrockError(
      'Could not update issuer instance capability set; ' +
      'set either not found or unexpected sequence number.',
      'InvalidStateError', details);
  }
};

// remove a capability set
exports.remove = async ({instanceId, userId, accountId}) => {
  assert.string(instanceId, 'instanceId');
  assert.optionalString(userId, 'userId');
  assert.optionalString(accountId, 'accountId');
  if(!userId && !accountId) {
    throw new TypeError('"userId" or "accountId" must be given.');
  }

  // update existing capability set to have no zcaps, revoking any as needed
  const oldRecord = await exports.get({instanceId, userId, accountId});
  const {capabilitySet} = oldRecord;
  capabilitySet.sequence++;
  capabilitySet.zcaps = [];
  await exports.update({capabilitySet});

  // remove capability set if sequence matches
  const query = {
    'capabilitySet.instance': instanceId,
    'capability.sequence': capabilitySet.sequences
  };
  if(accountId) {
    query.account = database.hash(accountId);
  }
  if(userId) {
    query['capabilitySet.user'] = userId;
  }
  const result = await database.collections.vcIssuerInstance.remove(query);
  if(result.result.n === 0) {
    const details = {instance: instanceId, httpStatusCode: 404, public: true};
    if(accountId) {
      details.account = accountId;
    }
    if(userId) {
      details.user = userId;
    }
    throw new BedrockError(
      'Issuer instance capability set with expected sequence not found.',
      'NotFoundError', details);
  }
};

function assertCapabilitySet(capabilitySet) {
  assert.object(capabilitySet, 'capabilitySet');
  assert.string(capabilitySet.instance, 'capabilitySet.instance');
  assert.string(capabilitySet.user, 'capabilitySet.user');
  assert.arrayOfObject(capabilitySet.zcaps, 'capabilitySet.zcaps');
  assert.optionalString(capabilitySet.account, 'capabilitySet.account');

  const {sequence} = capabilitySet;
  assert.number(sequence, 'capabilitySet.sequence');
  if(!(sequence >= 0 && Number.isInteger(sequence))) {
    throw new TypeError(
      '"capabilitySet.sequence" must be a non-negative integer.');
  }
}

function getZcapsToRevoke({oldSet, newSet}) {
  // return all zcaps in the old set that are not present in the new one
  const zcapSet = new Set(newSet.zcaps.map(({id}) => id));
  return oldSet.zcaps.filter(({id}) => !zcapSet.has(id));
}

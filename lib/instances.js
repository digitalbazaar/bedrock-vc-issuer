/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const assert = require('assert-plus');
const base64url = require('base64url-universal');
const bedrock = require('bedrock');
const crypto = require('crypto');
const database = require('bedrock-mongodb');
const {promisify} = require('util');
const {util: {BedrockError}} = bedrock;
const {CapabilityAgent} = require('webkms-client');
const {ensureKeystore} = require('./kms');
const {Ed25519KeyPair} = require('crypto-ld');

// load config defaults
require('./config');

// TODO: get KMS module from config
const kmsModule = 'ssm-v1';

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await promisify(database.openCollections)(
    ['vcIssuerInstance', 'vcIssuerCapabilitySet']);

  await promisify(database.createIndexes)([{
    // cover instance queries by id
    collection: 'vcIssuerInstance',
    fields: {'instance.id': 1},
    options: {unique: true, background: false}
  }, {
    // cover instance queries by issuer; not unique
    collection: 'vcIssuerInstance',
    fields: {issuer: 1},
    options: {
      partialFilterExpression: {issuer: {$exists: true}},
      unique: false,
      background: false
    }
  }, {
    // cover instance queries by controller; not unique
    collection: 'vcIssuerInstance',
    fields: {controller: 1},
    options: {unique: false, background: false}
  }, {
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

exports.create = async ({instance}) => {
  assert.object(instance, 'instance');

  // generate private `capabilityAgentSeed` for instance
  const capabilityAgentSeed = base64url.encode(crypto.randomBytes(32));

  // insert the instance and get the updated record
  const now = Date.now();
  const meta = {created: now, updated: now};
  let record = {
    controller: database.hash(instance.controller),
    meta,
    instance,
    capabilityAgentSeed
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
  // do not expose `capabilityAgentSeed`
  delete record.capabilityAgentSeed;

  // initialize instance
  record.instance.keys = await _initialize({id: instance.id});

  // return record
  return record;
};

// get a particular instance
exports.get = async ({id, controller}) => {
  assert.string(id, 'id');
  assert.optionalString(controller, 'controller');

  const query = {'instance.id': id};
  // TODO: determine `public` status of information in instance
  if(controller) {
    // only allow find if controller matches
    query.controller = {$in: [database.hash(controller)]};
  }
  const record = await database.collections.vcIssuerInstance.findOne(
    query, {_id: 0, instance: 1, meta: 1});
  if(!record) {
    throw new BedrockError(
      'Issuer instance not found.',
      'NotFoundError',
      {id, httpStatusCode: 404, public: true});
  }
  return record;
};

// get all issuer instances (optionally filtered by controller)
exports.getAll = async ({controller} = {}) => {
  const query = {};
  if(controller) {
    query.controller = database.hash(controller);
  }
  const records = await database.collections.vcIssuerInstance.find(
    query, {_id: 0, instance: 1, meta: 1}).toArray();
  return records;
};

// remove an issuer instance
exports.remove = async ({id, controller}) => {
  assert.string(id, 'id');
  assert.optionalString(controller, 'controller');

  const query = {'instance.id': id};
  if(controller) {
    // only allow remove if controller matches
    query.controller = {$in: [database.hash(controller)]};
  }
  const result = await database.collections.vcIssuerInstance.remove(query);
  if(result.result.n === 0) {
    throw new BedrockError(
      'Issuer instance not found.',
      'NotFoundError',
      {id, httpStatusCode: 404, public: true});
  }
};

// get a capability agent for an instance
exports.getCapabilityAgent = async ({id}) => {
  assert.string(id, 'id');

  const record = await database.collections.vcIssuerInstance.findOne(
    {'instance.id': id}, {_id: 0, capabilityAgentSeed: 1});
  if(!record) {
    throw new BedrockError(
      'Issuer instance not found.',
      'NotFoundError',
      {id, httpStatusCode: 404, public: true});
  }
  const {capabilityAgentSeed: secret} = record;
  return CapabilityAgent.fromSecret({secret, handle: id});
};

// get a keystore agent for an instance
exports.getKeystoreAgent = async ({id, capabilityAgent}) => {
  if(!capabilityAgent) {
    capabilityAgent = await exports.getCapabilityAgent({id});
  }
  return ensureKeystore({capabilityAgent});
};

// set issuer and capabilities (zcaps) for an instance
exports.setIssuer = async ({id, controller, issuer, zcaps}) => {
  assert.string(id, 'id');
  assert.string(issuer, 'issuer');
  assert.array(zcaps, 'zcaps');
  assert.optionalString(controller, 'controller');

  const query = {'instance.id': id};
  if(controller) {
    // only allow update if controller matches
    query.controller = database.hash(controller);
  }
  const result = await database.collections.vcIssuerInstance.update(query, {
    $set: {
      issuer: database.hash(issuer),
      'instance.issuer': issuer,
      'instance.zcaps': zcaps,
      'meta.updated': Date.now()
    }
  }, database.writeOptions);
  if(result.result.n === 0) {
    // TODO: If `controller` does not match, this error is used not
    // `NotAllowedError` ... do we want this?
    throw new BedrockError(
      'Issuer instance not found.',
      'NotFoundError',
      {id, httpStatusCode: 404, public: true});
  }
};

// get a capability for an instance by reference ID
exports.getCapability = async ({instance, id, referenceId}) => {
  assert.object(instance, 'instance');
  assert.optionalString(id, 'id');
  assert.optionalString(referenceId, 'referenceId');

  if(referenceId) {
    return instance.zcaps.find(c => c.referenceId === referenceId);
  }
  if(id) {
    return instance.zcaps.find(c => c.id === id);
  }
};

async function _initialize({id}) {
  try {
    const keystoreAgent = await exports.getKeystoreAgent({id});
    const [zcapKey, kak, hmac] = await Promise.all([
      keystoreAgent.generateKey(
        {type: 'Ed25519VerificationKey2018', kmsModule}),
      keystoreAgent.generateKey(
        {type: 'keyAgreement', kmsModule}),
      keystoreAgent.generateKey({type: 'hmac', kmsModule})
    ]);

    // create public ID (did:key) for zcap key
    const keyDesc = await zcapKey.getKeyDescription();
    const fingerprint = Ed25519KeyPair.fingerprintFromPublicKey(keyDesc);
    zcapKey.id = `did:key:${fingerprint}#${fingerprint}`;

    // add key metadata to instance
    const keys = {
      zcapKey: {
        id: zcapKey.id, type: zcapKey.type, kmsId: zcapKey.kmsId
      },
      kak: {
        id: kak.id, type: kak.type, kmsId: kak.kmsId
      },
      // FIXME: add support for `kmsId` to `Hmac`
      hmac: {id: hmac.id, type: hmac.type}
    };

    const result = await database.collections.vcIssuerInstance.update({
      'instance.id': id
    }, {
      $set: {
        'instance.keys': keys,
        'meta.updated': Date.now()
      }
    }, database.writeOptions);
    if(result.result.n === 0) {
      throw new BedrockError(
        'Issuer instance not found.',
        'NotFoundError',
        {id, httpStatusCode: 404, public: true});
    }
    return keys;
  } catch(e) {
    throw new BedrockError(
      'Issuer instance failed to initialize.',
      'InvalidStateError',
      {id, httpStatusCode: 500, public: true}, e);
  }
}

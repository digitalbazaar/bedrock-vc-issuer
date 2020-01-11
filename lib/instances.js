/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const base64url = require('base64url-universal');
const bedrock = require('bedrock');
const crypto = require('crypto');
const database = require('bedrock-mongodb');
const {promisify} = require('util');
const {util: {BedrockError}} = bedrock;
const https = require('https');
const {ControllerKey, KmsClient} = require('webkms-client');
const {ensureKeystore} = require('./kms');
const {Ed25519KeyPair} = require('crypto-ld');

// load config defaults
require('./config');

// TODO: get KMS module from config
const kmsModule = 'ssm-v1';

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await promisify(database.openCollections)(['vcIssuerInstance']);

  await promisify(database.createIndexes)([{
    // cover queries by id
    collection: 'vcIssuerInstance',
    fields: {'instance.id': 1},
    options: {unique: true, background: false}
  }, {
    // cover queries by issuer; not unique
    collection: 'vcIssuerInstance',
    fields: {issuer: 1},
    options: {
      partialFilterExpression: {issuer: {$exists: true}},
      unique: false,
      background: false
    }
  }, {
    // cover queries by controller; not unique
    collection: 'vcIssuerInstance',
    fields: {controller: 1},
    options: {unique: false, background: false}
  }]);
});

exports.create = async ({instance}) => {
  // generate private `controllerKeySeed` for instance
  const controllerKeySeed = base64url.encode(crypto.randomBytes(32));

  // insert the instance and get the updated record
  const now = Date.now();
  const meta = {created: now, updated: now};
  let record = {
    controller: database.hash(instance.controller),
    meta,
    instance,
    controllerKeySeed
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
  // do not expose `controllerKeySeed`
  delete record.controllerKeySeed;

  // initialize instance
  record.instance.keys = await _initialize({id: instance.id});

  // return record
  return record;
};

// get a particular instance
exports.get = async ({id, controller}) => {
  const query = {'instance.id': id};
  // TODO: determine `public` status of information in instance
  if(controller) {
    // only allow find if controller matches
    query.controller = {$in: [controller]};
  }
  const record = await database.collections.vcIssuerInstance.findOne(
    query, {_id: 0, instance: 1});
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
  if(!(id && typeof id === 'string')) {
    throw new TypeError('"id" must be a string.');
  }
  const query = {'instance.id': id};
  if(controller) {
    // only allow remove if controller matches
    query.controller = {$in: [controller]};
  }
  const result = await database.collections.vcIssuerInstance.remove(query);
  return result.result.n !== 0;
};

// get a controller key for an instance
exports.getControllerKey = async ({id}) => {
  const record = await database.collections.vcIssuerInstance.findOne(
    {'instance.id': id}, {_id: 0, controllerKeySeed: 1});
  if(!record) {
    throw new BedrockError(
      'Issuer instance not found.',
      'NotFoundError',
      {id, httpStatusCode: 404, public: true});
  }
  const {controllerKeySeed: secret} = record;
  const kmsClient = new KmsClient({
    httpsAgent: new https.Agent({
      // TODO: base on bedrock configuration
      rejectUnauthorized: false
    })
  });
  const controllerKey = await ControllerKey.fromSecret(
    {secret, handle: id, kmsClient});
  await ensureKeystore({controllerKey});
  return controllerKey;
};

// set issuer and capabilities (zcaps) for an instance
exports.setIssuer = async ({id, controller, issuer, zcaps}) => {
  const query = {'instance.id': id};
  if(controller) {
    // only allow update if controller matches
    query.controller = {$in: [controller]};
  }
  const result = await database.collections.vcIssuerInstance.update(query, {
    $set: {
      issuer: database.hash(issuer),
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

async function _initialize({id}) {
  try {
    const controllerKey = await exports.getControllerKey({id});
    const [zcapKey, kak, hmac] = await Promise.all([
      controllerKey.generateKey(
        {type: 'Ed25519VerificationKey2018', kmsModule}),
      controllerKey.generateKey(
        {type: 'keyAgreement', kmsModule}),
      controllerKey.generateKey({type: 'hmac', kmsModule})
    ]);

    // TODO: enable getting key description from AsymmetricKey object to
    // avoid additional call to get key description
    const keyDesc = await controllerKey.kmsClient.getKeyDescription(
      {keyId: zcapKey.id, invocationSigner: controllerKey});

    // create public ID (did:key) for zcap key
    const fingerprint = Ed25519KeyPair.fingerprintFromPublicKey(keyDesc);
    zcapKey.id = `did:key:${fingerprint}`;

    // add key metadata to instance
    const keys = {
      zcapKey: {
        id: zcapKey.id, type: zcapKey.type, kmsId: zcapKey.id
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

/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

//const _logger = require('./logger');
const base64url = require('base64url-universal');
const bedrock = require('bedrock');
const brAccount = require('bedrock-account');
const crypto = require('crypto');
//const database = require('bedrock-mongodb');
const https = require('https');
const jsonpatch = require('fast-json-patch');
//const {promisify} = require('util');
//const {util: {BedrockError}} = bedrock;
const {ControllerKey, KmsClient} = require('webkms-client');
const {EdvClient, EdvDocument} = require('edv-client');
const {ensureKeystore} = require('./kms');

// load config defaults
//require('./config');

// TODO: get KMS module from config
const kmsModule = 'ssm-v1';

bedrock.events.on('bedrock-account.insert', async ({account}) => {
  // add `controllerKeySeed` to account so a controller key can be used
  const seed = base64url.encode(crypto.randomBytes(32));
  account.controllerKeySeed = seed;
});

bedrock.events.on('bedrock-account.postInsert', async ({account: {id}}) => {
  const {account, meta} = await brAccount.get({actor: null, id});
  const {sequence} = meta;
  const controllerKey = await exports.getControllerKey({account});
  let {kak, hmac} = account;

  const observer = jsonpatch.observe(account);
  const patch = jsonpatch.generate(observer);
  if(kak) {
    kak = await controllerKey.getKeyAgreementKey({id: kak.id, type: kak.type});
  } else {
    kak = await controllerKey.generateKey({type: 'keyAgreement', kmsModule});
  }
  if(hmac) {
    hmac = await controllerKey.getHmac({id: hmac.id, type: hmac.type});
  } else {
    hmac = await controllerKey.generateKey({type: 'hmac', kmsModule});
  }
  account.kak = {id: kak.id, type: kak.type};
  account.hmac = {id: hmac.id, type: hmac.type};
  jsonpatch.unobserve(account, observer);
  await brAccount.update({
    actor: null,
    id,
    patch,
    sequence
  });
});

/**
 * @module bedrock-wallet-client
 */

exports.getControllerKey = async function({actor, accountId, account = null}) {
  if(!account) {
    ({account} = await brAccount.get({actor, id: accountId}));
  }
  const {controllerKeySeed: secret} = account;
  const kmsClient = new KmsClient({
    httpsAgent: new https.Agent({
      // TODO: base on bedrock configuration
      rejectUnauthorized: false
    })
  });
  const controllerKey = await ControllerKey.fromSecret(
    {secret, handle: account.id, kmsClient});
  // FIXME: keystore should be created for an `instance`, not per controller
  // key ... the account that creates the `instance` will use its controller
  // key as the controller for the instance's keystore ... and can add `peers`
  // as other controllers... so this should be moved out to instance
  // creation code
  await ensureKeystore({controllerKey});
  return controllerKey;
};

// EDV storage
// read or write single documents
const storage = exports.storage = {};

storage.set = async (
  {actor, accountId, instance, id, capability, content, sequence = 0}) => {
  const edvDoc = await _getEdvDocument(
    {actor, accountId, instance, id, capability});

  let currentDoc = {};
  if(sequence === 0) {
    currentDoc = {id: edvDoc.id};
  } else {
    currentDoc = await edvDoc.read();
    if(sequence !== currentDoc.sequence) {
      // TODO: use BedrockError unless bedrock-account is abstracted away
      const err = new Error('Conflict error.');
      err.name = 'InvalidStateError';
      throw err;
    }
  }

  const doc = {
    ...currentDoc,
    content
  };
  return edvDoc.write({doc});
};

storage.get = async ({actor, accountId, instance, id, capability}) => {
  const doc = await _getEdvDocument(
    {actor, accountId, instance, id, capability});
  return doc.read();
};

storage.find = async ({
  actor, accountId, instance, type, equals, has, capability
}) => {
  if(!(equals || has || type)) {
    throw new TypeError('"equals", "has", or "type" must be given.');
  }
  if(!equals) {
    equals = [];
  } else {
    equals = equals.slice();
  }
  if(type) {
    if(Array.isArray(type)) {
      const query = type.map(type => ({'content.type': type}));
      equals.push(...query);
    } else {
      equals.push({'content.type': type});
    }
  }
  const {account} = await brAccount.get({actor, id: accountId});
  const invocationSigner = await exports.getControllerKey({account});
  const client = await _getEdvClient({account, instance});
  const results = await client.find(
    {equals, has, capability, invocationSigner});
  return results;
};

async function _getEdvDocument({actor, accountId, instance, id, capability}) {
  const {account} = await brAccount.get({actor, id: accountId});
  const controllerKey = await exports.getControllerKey({account});
  const client = await _getEdvClient({account, instance});
  const {keyAgreementKey, hmac} = client;
  const invocationSigner = controllerKey;
  const recipients = [{
    header: {kid: keyAgreementKey.id, alg: 'ECDH-ES+A256KW'}
  }];
  return new EdvDocument({
    id, recipients, keyResolver, keyAgreementKey, hmac, capability,
    invocationSigner, client
  });
}

async function _getEdvClient({account, instance}) {
  const controllerKey = await exports.getControllerKey({account});
  // FIXME: instead of using KeyAgreementKey and HMAC for the account ...
  // use it for the issuer `instance` ... and give zcaps to the controller
  // key to do so... users with `read` only need HMAC `verify` and KaK `derive`
  // and users with `write` need HMAC `sign`... then controller key also
  // needs zcap for the vault... pass `capability` to `getKeyAgreementKey`
  // and `getHmac` keys below... the `account` did:key that creates the
  // instance is the first `controller` of the instance's keystore
  const [keyAgreementKey, hmac] = await Promise.all([
    await controllerKey.getKeyAgreementKey(
      {id: account.kak.id, type: account.kak.type}),
    await controllerKey.getHmac({id: account.hmac.id, type: account.hmac.type})
  ]);
  // TODO: base this off of bedrock.config
  const httpsAgent = new https.Agent({
    rejectUnauthorized: false
  });
  const client = new EdvClient(
    {keyResolver, keyAgreementKey, hmac, httpsAgent});
  // create indexes for documents
  client.ensureIndex({attribute: 'content.type'});
  client.ensureIndex({attribute: 'content.id', unique: true});
  // TODO: index based on supported credential types for the instance
  // TODO: will need to be able to get all
  // `content.type === 'VerifiableCredential'` and reindex as needed
  return client;
}

// FIXME: make more restrictive, support `did:key` and `did:v1`
async function keyResolver({id}) {
  const remoteDoc = await bedrock.jsonld.documentLoader(id);
  return remoteDoc.document;
}

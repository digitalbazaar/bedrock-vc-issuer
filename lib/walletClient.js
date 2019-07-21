/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
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
const {ControllerKey, KmsClient} = require('web-kms-client');
const {DataHubClient, DataHubDocument} = require('secure-data-hub-client');

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
  await _ensureKeystore({controllerKey});
  return controllerKey;
};

// DataHub storage
// read or write single documents
const storage = exports.storage = {};

storage.set = async ({actor, accountId, capability, content, sequence = 0}) => {
  const dataHubDoc = await _getDataHubDocument({actor, accountId, capability});

  let currentDoc = {};
  if(sequence === 0) {
    currentDoc = {id: dataHubDoc.id};
  } else {
    currentDoc = await dataHubDoc.read();
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
  return dataHubDoc.write({doc});
};

storage.get = async ({actor, accountId, capability}) => {
  const doc = await _getDataHubDocument({actor, accountId, capability});
  return doc.read();
};

async function _getDataHubDocument({actor, accountId, capability}) {
  const {account} = await brAccount.get({actor, id: accountId});
  const controllerKey = await exports.getControllerKey({account});
  const [keyAgreementKey, hmac] = await Promise.all([
    await controllerKey.getKeyAgreementKey(
      {id: account.kak.id, type: account.kak.type}),
    await controllerKey.getHmac({id: account.hmac.id, type: account.hmac.type})
  ]);
  // TODO: base this off of bedrock.config
  const httpsAgent = new https.Agent({
    rejectUnauthorized: false
  });
  const client = new DataHubClient({httpsAgent});
  const invocationSigner = controllerKey;
  const recipients = [{
    header: {kid: keyAgreementKey.id, alg: 'ECDH-ES+A256KW'}
  }];
  return new DataHubDocument({
    recipients, keyResolver, keyAgreementKey, hmac, capability,
    invocationSigner, client
  });
}

async function _createKeystore({controllerKey, referenceId} = {}) {
  const kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`;

  // create keystore
  const config = {
    sequence: 0,
    controller: controllerKey.id,
    // TODO: add `invoker` and `delegator` using arrays including
    // controllerKey.id *and* identifier for backup key recovery entity
    invoker: controllerKey.id,
    delegator: controllerKey.id
  };
  if(referenceId) {
    config.referenceId = referenceId;
  }
  // TODO: base this off of bedrock.config
  const httpsAgent = new https.Agent({
    rejectUnauthorized: false
  });
  return await KmsClient.createKeystore({
    url: `${kmsBaseUrl}/keystores`,
    config,
    httpsAgent
  });
}

async function _ensureKeystore({controllerKey}) {
  const kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`;

  // TODO: base this off of bedrock.config
  const httpsAgent = new https.Agent({
    rejectUnauthorized: false
  });
  let config = await KmsClient.findKeystore({
    url: `${kmsBaseUrl}/keystores`,
    controller: controllerKey.id,
    referenceId: 'primary',
    httpsAgent
  });
  if(config === null) {
    config = await _createKeystore({controllerKey, referenceId: 'primary'});
  }
  if(config === null) {
    return null;
  }
  controllerKey.kmsClient.keystore = config.id;
  return config;
}

// FIXME: make more restrictive, support `did:key` and `did:v1`
async function keyResolver({id}) {
  const remoteDoc = await bedrock.jsonld.documentLoader(id);
  return remoteDoc.document;
}

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
//const jsonpatch = require('fast-json-patch');
//const {promisify} = require('util');
//const {util: {BedrockError}} = bedrock;
const {ControllerKey, KmsClient} = require('webkms-client');
const {EdvClient, EdvDocument} = require('edv-client');
//const {ensureKeystore} = require('./kms');

// load config defaults
//require('./config');

// TODO: get KMS module from config
//const kmsModule = 'ssm-v1';

// FIXME: generate a zcap invoke/delegate key instead of kak/hmac...
// the kak/hmac are provided by instances, not by accounts
/*
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
*/

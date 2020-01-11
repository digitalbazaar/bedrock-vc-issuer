/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const https = require('https');
const {KmsClient} = require('webkms-client');

// load config defaults
require('./config');

exports.createKeystore = async ({controllerKey, referenceId} = {}) => {
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
};

exports.ensureKeystore = async ({controllerKey}) => {
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
    config = await exports.createKeystore(
      {controllerKey, referenceId: 'primary'});
  }
  if(config === null) {
    return null;
  }
  controllerKey.kmsClient.keystore = config.id;
  return config;
};

/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const path = require('path');
require('bedrock-vc-issuer');

// MongoDB
config.mongodb.name = 'bedrock_vc_issuer_test';
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];
// drop all collections on initialization
config.mongodb.dropCollections = {};
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];

config.mocha.options.fullTrace = true;
config.mocha.tests.push(path.join(__dirname, 'mocha'));

// allow self-signed certs in test framework
config['https-agent'].rejectUnauthorized = false;

// create test application identity
// ...and `ensureConfigOverride` has already been set via
// `bedrock-app-identity` so it doesn't have to be set here
config['app-identity'].seeds.services['vc-issuer'] = {
  id: 'did:key:z6MkrH839XwPCUQ2TkA6ifehciWnEvzuQ2njc6J19fpuP5oN',
  seedMultibase: 'z1AgvAGfbairK3AV6GqbeF8gSpYZXftQsGb5DTjptgawNyn',
  serviceType: 'vc-issuer'
};

// use local KMS for testing
config['service-agent'].kms.baseUrl = 'https://localhost:18443/kms';

/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const path = require('path');

config.mocha.tests.push(path.join(__dirname, 'mocha'));

// MongoDB
config.mongodb.name = 'bedrock_vc_issuer_test';
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];

config['https-agent'].rejectUnauthorized = false;

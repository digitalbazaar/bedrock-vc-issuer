/*
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const path = require('path');

const namespace = 'vc-issuer';
config[namespace] = {};

// common validation schemas
config.validation.schema.paths.push(
  path.join(__dirname, '..', 'schemas')
);

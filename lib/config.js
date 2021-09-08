/*
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const path = require('path');
const {Ed25519VerificationKey2020} =
  require('@digitalbazaar/ed25519-verification-key-2020');
const {CryptoLD} = require('crypto-ld');

const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);

const namespace = 'vc-issuer';
const cfg = config[namespace] = {};

// bedrock-did-io configuration
config['did-io'].methods.key.verificationSuite = Ed25519VerificationKey2020;

config['did-io'].methods.v1.verificationSuite = Ed25519VerificationKey2020;
config['did-io'].methods.v1.cryptoLd = cryptoLd;

// allow self-signed certificates in dev
config['https-agent'].rejectUnauthorized = false;

// document loader configuration for the issuer
cfg.documentLoader = {};

// document loading mode options:
//   local - do not fetch documents from the network
//   web - fetch documents from the global Web
cfg.documentLoader.mode = 'web';

// common validation schemas
config.validation.schema.paths.push(
  path.join(__dirname, '..', 'schemas')
);

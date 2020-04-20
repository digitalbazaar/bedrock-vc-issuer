/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
const bedrock = require('bedrock');

require('bedrock-https-agent');
require('bedrock-kms');
require('bedrock-kms-http');
require('bedrock-mongodb');
require('bedrock-vc-issuer');

require('bedrock-test');
bedrock.start();

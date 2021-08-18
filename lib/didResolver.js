/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const didIo = require('did-io');
didIo.use(require('@digitalbazaar/did-method-key').driver());
const v1 = require('did-veres-one');

// load config defaults
require('./config');

const resolvers = [];

bedrock.events.on('bedrock.start', () => {
  const {'vc-issuer': cfg} = config;
  resolvers.push(_createDidLoader({
    hostname: cfg.ledgerHostname,
    mode: cfg.mode,
  }));
});

exports.resolve = async url => {
  let result;
  for(const resolver of resolvers) {
    try {
      result = await resolver(url);
    } catch(e) {
      // this loader failed move on to the next
      continue;
    }
    if(result) {
      return result;
    }
  }
  // failure, throw
  throw new Error(`Document not found: ${url}`);
};

function _createDidLoader({hostname, mode = 'test'}) {
  didIo.use(v1.driver({hostname, mode}));
  return async url => {
    if(!url.startsWith('did:')) {
      throw new Error('NotFoundError');
    }
    let document;
    try {
      document = await didIo.get({did: url});
    } catch(e) {
      console.error(e);
      throw new Error('NotFoundError');
    }
    return {
      contextUrl: null,
      documentUrl: url,
      document
    };
  };
}

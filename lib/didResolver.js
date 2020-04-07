/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const didKeyDriver = require('did-method-key').driver();

// load config defaults
require('./config');
const {'vc-issuer': cfg} = config;

const resolvers = [];

bedrock.events.on('bedrock.start', () => {
  if(cfg.ledgerHostname && cfg.mode) {
    // push a v1 ledger resolvers
    resolvers.push(_createV1Loader({
      hostname: cfg.ledgerHostname,
      mode: cfg.mode,
    }));
  }
  // add resolver for `did:key:`
  resolvers.push(_didKeyLoader);
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

function _createV1Loader({hostname, mode}) {
  const v1 = new (require('did-veres-one')).VeresOne({hostname, mode});
  return async url => {
    if(!url.startsWith('did:v1:')) {
      throw new Error('NotFoundError');
    }
    let result;
    try {
      result = await v1.get({did: url});
    } catch(e) {
      throw new Error('NotFoundError');
    }
    return {
      contextUrl: null,
      // toJSON() returns just the `doc` portion of the instance
      document: result.toJSON(),
      documentUrl: url
    };
  };
}

async function _didKeyLoader(url) {
  if(!url.startsWith('did:key:')) {
    throw new Error('NotFoundError');
  }
  let result;
  try {
    result = await didKeyDriver.get({url});
  } catch(e) {
    throw new Error('NotFoundError');
  }
  return {
    contextUrl: null,
    document: result,
    documentUrl: url
  };
}

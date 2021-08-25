/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {didIo} = require('bedrock-did-io');

// load config defaults
require('./config');

const resolvers = [];

bedrock.events.on('bedrock.start', () => {
  resolvers.push(_createDidLoader());
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

function _createDidLoader() {
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

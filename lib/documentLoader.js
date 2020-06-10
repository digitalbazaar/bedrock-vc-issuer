/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const axios = require('axios');
const bedrock = require('bedrock');
const jsonld = require('jsonld');
const {
  documentLoader: bedrockLoader
} = require('bedrock-jsonld-document-loader');
const {config} = bedrock;
const {'vc-issuer': cfg} = config;

const api = {};
module.exports = api;

api.loaders = [];

bedrock.events.on('bedrock.start', () => {
  api.loaders.push(bedrockLoader);
  // FIXME: use computed config API instead of eventing this

  // if enabled, add loader for remote documents
  if(cfg.documentLoader.mode === 'web') {
    api.loaders.push(_webLoader);
  }
});

api.documentLoader = async url => {
  let result;
  for(const loader of api.loaders) {
    try {
      result = await loader(url);
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

async function _webLoader(url) {
  if(!url.startsWith('http')) {
    throw new Error('NotFoundError');
  }
  let result;
  try {
    result = await axios(url);
  } catch(e) {
    throw new Error('NotFoundError');
  }

  return {
    contextUrl: null,
    document: result.data,
    documentUrl: url
  };
}

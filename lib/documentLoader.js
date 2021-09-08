/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {
  jsonLdDocumentLoader,
  httpClientHandler
} = require('bedrock-jsonld-document-loader');
// Includes support for did:key and did:v1
const {didIo} = require('bedrock-did-io');

const {config} = bedrock;

bedrock.events.on('bedrock.start', () => {
  const {'vc-issuer': cfg} = config;

  jsonLdDocumentLoader.setDidResolver(didIo);

  // if enabled, add loader for remote documents
  if(cfg.documentLoader.mode === 'web') {
    jsonLdDocumentLoader.setProtocolHandler({
      protocol: 'http', handler: httpClientHandler});
    jsonLdDocumentLoader.setProtocolHandler({
      protocol: 'https', handler: httpClientHandler});
  }
});

const documentLoader = jsonLdDocumentLoader.build();

module.exports = {documentLoader};

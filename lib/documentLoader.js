/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {
  jsonLdDocumentLoader,
  webProtocolHandler
} = require('bedrock-jsonld-document-loader');

const {config} = bedrock;
const {'vc-issuer': cfg} = config;

// if enabled, add loader for remote documents
if(cfg.documentLoader.mode === 'web') {
  jsonLdDocumentLoader.setProtocolHandler({
    protocol: 'http', handler: webProtocolHandler});
  jsonLdDocumentLoader.setProtocolHandler({
    protocol: 'https', handler: webProtocolHandler});
}

const documentLoader = jsonLdDocumentLoader.build();

module.exports = {documentLoader};

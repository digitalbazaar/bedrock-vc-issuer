/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  documentLoader as brDocLoader,
  httpClientHandler,
  JsonLdDocumentLoader
} from '@bedrock/jsonld-document-loader';
import {createContextDocumentLoader} from '@bedrock/service-context-store';
import {didIo} from '@bedrock/did-io';

import '@bedrock/credentials-context';
import '@bedrock/data-integrity-context';
import '@bedrock/did-context';
import '@bedrock/did-io';
import '@bedrock/security-context';
import '@bedrock/vc-status-list-context';
import '@bedrock/vc-revocation-list-context';
import '@bedrock/veres-one-context';
import '@bedrock/multikey-context';

const serviceType = 'vc-issuer';
let webLoader;

bedrock.events.on('bedrock.init', () => {
  // build web loader if configuration calls for it
  const cfg = bedrock.config['vc-issuer'];
  if(cfg.documentLoader.http || cfg.documentLoader.https) {
    const jdl = new JsonLdDocumentLoader();
    if(cfg.documentLoader.http) {
      jdl.setProtocolHandler({protocol: 'http', handler: httpClientHandler});
    }
    if(cfg.documentLoader.https) {
      jdl.setProtocolHandler({protocol: 'https', handler: httpClientHandler});
    }

    webLoader = jdl.build();
  }
});

/**
 * Creates a document loader for the issuer instance identified via the
 * given config.
 *
 * @param {object} options - The options to use.
 * @param {object} options.config - The issuer instance config.
 *
 * @returns {Promise<Function>} The document loader.
 */
export async function createDocumentLoader({config} = {}) {
  const contextDocumentLoader = await createContextDocumentLoader(
    {config, serviceType});

  return async function documentLoader(url) {
    // resolve all DID URLs through did-io
    if(url.startsWith('did:')) {
      const document = await didIo.get({url});
      return {
        contextUrl: null,
        documentUrl: url,
        document
      };
    }

    try {
      // try to resolve URL through built-in doc loader
      return await brDocLoader(url);
    } catch(e) {
      // FIXME: improve to check for `NotFoundError` once `e.name`
      // supports it
    }

    try {
      // try to resolve URL through context doc loader
      return await contextDocumentLoader(url);
    } catch(e) {
      // use web loader if configured
      if(url.startsWith('http') && e.name === 'NotFoundError' && webLoader) {
        return webLoader(url);
      }
      throw e;
    }
  };
}

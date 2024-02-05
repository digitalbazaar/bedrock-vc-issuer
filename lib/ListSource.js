/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as slcs from './slcs.js';
import {
  createList as createList2020,
  createCredential as createRlc
} from '@digitalbazaar/vc-revocation-list';
import {
  createList as createList2021,
  createCredential as createSlc
} from '@digitalbazaar/vc-status-list';
import assert from 'assert-plus';
import {issue} from './helpers.js';

export class ListSource {
  constructor({
    slcsBaseUrl, documentLoader, documentStore,
    issuer, statusListConfig, suite
  } = {}) {
    assert.string(slcsBaseUrl, 'slcsBaseUrl');
    assert.func(documentLoader, 'documentLoader');
    assert.object(documentStore, 'documentStore');
    assert.object(statusListConfig, 'statusListConfig');
    assert.string(issuer, 'issuer');
    assert.object(suite, 'suite');
    if(!slcsBaseUrl) {
      throw new TypeError('"slcsBaseUrl" must be a non-empty string.');
    }
    if(!issuer) {
      throw new TypeError('"issuer" must be a non-empty string.');
    }
    this.slcsBaseUrl = slcsBaseUrl;
    this.documentLoader = documentLoader;
    this.documentStore = documentStore;
    this.issuer = issuer;
    this.statusListConfig = statusListConfig;
    this.suite = suite;
  }

  async createStatusList({id, statusPurpose, length}) {
    // FIXME: call out to status service
    await this._ensureStatusListCredentialExists({id, statusPurpose, length});
  }

  // FIXME: move to status service
  async _createStatusListCredential({id, type, statusPurpose, length}) {
    if(type === 'RevocationList2020') {
      const list = await createList2020({length});
      return createRlc({id, list});
    }
    // FIXME: implement `BitstringStatusList`
    // assume `StatusList2021`
    const list = await createList2021({length});
    return createSlc({id, list, statusPurpose});
  }

  // FIXME: status service should handle this instead
  async _ensureStatusListCredentialExists({id, statusPurpose, length}) {
    // get `edvClient` directly; do not use cache in `documentStore` to ensure
    // latest docs are used
    const {documentLoader, documentStore: {edvClient}} = this;

    // try to create SLC credential and EDV doc...
    const {suite, issuer} = this;
    // FIXME: create list without having to issue VC; issue VC on demand
    // instead
    const credential = await this._createStatusListCredential({
      id, statusPurpose, length
    });
    credential.issuer = issuer;
    credential.name = 'Status List Credential';
    credential.description =
      `This credential expresses status information for some ` +
      'other credentials in an encoded and compressed list.';
    // express date without milliseconds
    const now = (new Date()).toJSON();
    credential.issuanceDate = `${now.slice(0, -5)}Z`;
    const verifiableCredential = await issue(
      {credential, documentLoader, suite});
    let doc = {
      id: await edvClient.generateId(),
      content: verifiableCredential,
      // include `meta.type` as a non-user input type to validate against
      meta: {type: 'VerifiableCredential'}
    };
    try {
      doc = await edvClient.update({doc});
    } catch(e) {
      if(e.name !== 'DuplicateError') {
        throw e;
      }
      // duplicate, ignore as another process created the SLC... get it
      doc = await edvClient.get({id: doc.id});
    }

    // ensure SLC is published
    const isPublished = await slcs.exists({id});
    if(!isPublished) {
      const {content: credential, sequence} = doc;
      try {
        // store SLC Doc for public serving
        await slcs.set({credential, sequence});
      } catch(e) {
        // safe to ignore conflicts, a newer version of the SLC was published
        // than the one that was retrieved
        if(e.name === 'InvalidStateError' || e.name === 'DuplicateError') {
          return;
        }
        throw e;
      }
    }
  }
}

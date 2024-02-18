/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import {CredentialStatusWriter} from './CredentialStatusWriter.js';
import {getIssuerAndSuite} from './helpers.js';
import {ListSource} from './ListSource.js';
import {logger} from './logger.js';
import {constants as rlConstants} from '@bedrock/vc-revocation-list-context';
import {constants as slConstants} from '@bedrock/vc-status-list-context';

export class CredentialStatusIssuer {
  constructor({config, documentLoader, edvClient} = {}) {
    assert.object(config, 'config');
    assert.func(documentLoader, 'documentLoader');
    assert.object(edvClient, 'edvClient');
    this.config = config;
    this.documentLoader = documentLoader;
    this.edvClient = edvClient;
    this.credential = null;
    this.writers = [];
    this.statusResultMap = null;
    this.duplicateResultMap = null;
  }

  async initialize({credential} = {}) {
    assert.object(credential, 'credential');
    this.credential = credential;

    // see if config indicates a credential status should be set
    const {config, documentLoader, edvClient, writers} = this;
    const {statusListOptions = []} = config;

    if(statusListOptions.length === 0) {
      // nothing to do, no credential statuses to be written
      return;
    }

    // create VC status writer(s); there may be N-many credential status
    // writers, one for each status for the same credential, each will write
    // a result into the status result map
    this.statusResultMap = new Map();

    // `type` defaults to `RevocationList2020`
    for(const statusListConfig of statusListOptions) {
      const {type = 'RevocationList2020', suiteName} = statusListConfig;
      if(type === 'RevocationList2020') {
        if(!credential['@context'].includes(
          rlConstants.VC_REVOCATION_LIST_CONTEXT_V1_URL)) {
          credential['@context'].push(
            rlConstants.VC_REVOCATION_LIST_CONTEXT_V1_URL);
        }
      } else {
        if(!credential['@context'].includes(slConstants.CONTEXT_URL_V1)) {
          credential['@context'].push(slConstants.CONTEXT_URL_V1);
        }
      }

      // FIXME: this process should use the status list config to setup
      // list sources (that use zcaps/oauth privileges create lists on demand)
      // FIXME: the status service will need to issue and serve the SLC on
      // demand -- and use cases may require redirection URLs for this
      // FIXME: the status service will need access to its own other issuer
      // instance for issuing SLCs
      // FIXME: remove `issuer` and `suite` these will be handled by a status
      // service instead
      const {issuer, suite} = await getIssuerAndSuite({config, suiteName});
      const listSource = new ListSource({
        statusListConfig, documentLoader, edvClient, issuer, suite
      });
      writers.push(new CredentialStatusWriter({
        statusListConfig,
        documentLoader,
        edvClient,
        listSource
      }));
    }
  }

  async issue() {
    // ensure every credential status writer has a result in the result map
    const {credential, writers, duplicateResultMap, statusResultMap} = this;
    if(writers.length === 0) {
      // no status to write
      return [];
    }

    // code assumes there are only a handful of statuses such that no work queue
    // is required; but ensure all writes finish before continuing since this
    // code can run in a loop and cause overwrite bugs with slow database calls
    const results = await Promise.allSettled(writers.map(async w => {
      if(statusResultMap.has(w)) {
        return;
      }
      const duplicateResult = duplicateResultMap?.get(w);
      statusResultMap.set(w, await w.write({credential, duplicateResult}));
    }));

    // throw any errors for failed writes
    for(const {status, reason} of results) {
      if(status === 'rejected') {
        throw reason;
      }
    }

    // produce combined `credentialStatus` meta
    const credentialStatus = [];
    for(const [, statusResult] of statusResultMap) {
      credentialStatus.push(...statusResult.statusEntries.map(
        ({meta: {credentialStatus}}) => credentialStatus));
    }
    console.log('combined credential status meta', credentialStatus);
    return credentialStatus;
  }

  async hasDuplicate() {
    this.duplicateResultMap = new Map();

    // check every status map result and remove any duplicates to allow a rerun
    // for those writers
    const {statusResultMap} = this;
    const entries = [...statusResultMap.entries()];
    const results = await Promise.allSettled(entries.map(
      async ([w, statusResult]) => {
        const exists = await w.exists({statusResult});
        if(exists) {
          // FIXME: remove logging
          console.log('+++duplicate credential status',
            statusResultMap.get(w));
          // move duplicate result into duplicate result map
          this.duplicateResultMap.set(w, statusResult);
          statusResultMap.delete(w);
        }
        return exists;
      }));
    for(const {status, reason, value} of results) {
      // if checking for a duplicate failed for any writer, we can't handle it
      // gracefully; throw
      if(status === 'rejected') {
        throw reason;
      }
      if(value) {
        return true;
      }
    }
    console.log('---no duplicate credential status');
    return false;
  }

  finish() {
    const {writers} = this;
    if(writers.length === 0) {
      return;
    }
    // do not wait for status writing to complete (this would be an unnecessary
    // performance hit)
    writers.map(w => w.finish().catch(error => {
      // logger errors for later analysis, but do not throw them; credential
      // status write can be continued later by another process
      logger.error(error.message, {error});
    }));
  }
}

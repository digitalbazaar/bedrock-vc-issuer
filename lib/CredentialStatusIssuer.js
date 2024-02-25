/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  bslConstants, constants as slConstants
} from '@bedrock/vc-status-list-context';
import assert from 'assert-plus';
import {CredentialStatusWriter} from './CredentialStatusWriter.js';
import {ListSource} from './ListSource.js';
import {logger} from './logger.js';
import {constants as vcConstants} from '@bedrock/credentials-context';

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

    for(const statusListConfig of statusListOptions) {
      const {type} = statusListConfig;
      const {'@context': contexts} = credential;
      if(type === 'StatusList2021') {
        if(!contexts.includes(slConstants.CONTEXT_URL_V1)) {
          contexts.push(slConstants.CONTEXT_URL_V1);
        }
      } else if(type === 'BitstringStatusList') {
        // ensure bitstring status context is present for v1 VCs
        if(contexts.includes(vcConstants.CREDENTIALS_CONTEXT_V1_URL) &&
          !contexts.includes(bslConstants.CONTEXT_URL)) {
          contexts.push(bslConstants.CONTEXT_URL);
        }
      }
      // note: no changes for `TerseBitstringStatusList`, the contexts required
      // must be stored in the issuer instance and URLs provided in the VC
      const listSource = new ListSource({config, statusListConfig});
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

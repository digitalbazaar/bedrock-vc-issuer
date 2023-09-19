/*!
 * Copyright (c) 2020-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as slcs from './slcs.js';
import {issue as _issue, getCredentialStatusInfo} from './helpers.js';
import {AsymmetricKey, KmsClient} from '@digitalbazaar/webkms-client';
import {documentStores, serviceAgents} from '@bedrock/service-agent';
import assert from 'assert-plus';
import {createDocumentLoader} from './documentLoader.js';
import {CredentialStatusWriter} from './CredentialStatusWriter.js';
import {decodeList} from '@digitalbazaar/vc-status-list';
import {didIo} from '@bedrock/did-io';
import {getSuiteParams} from './suites.js';
import {httpsAgent} from '@bedrock/https-agent';
import {logger} from './logger.js';
import {constants as rlConstants} from '@bedrock/vc-revocation-list-context';
import {constants as slConstants} from '@bedrock/vc-status-list-context';

const {util: {BedrockError}} = bedrock;

const serviceType = 'vc-issuer';

// exported for testing purposes
export const _CredentialStatusWriter = CredentialStatusWriter;

export async function issue({credential, config} = {}) {
  assert.object(credential, 'credential');
  assert.object(config, 'config');

  // see if config indicates a credential status should be set
  const {statusListOptions = []} = config;

  const {suiteName} = config.issueOptions;
  const [documentLoader, documentStore, {issuer, suite}] = await Promise.all([
    createDocumentLoader({config}),
    // only fetch `documentStore` if a status list is configured; otherwise,
    // it is not needed
    statusListOptions.length > 0 ? _getDocumentStore({config}) : {},
    _getIssuerAndSuite({config, suiteName})
  ]);
  const {edvClient} = documentStore;

  if(typeof credential.issuer === 'object') {
    credential.issuer = {
      ...credential.issuer,
      id: issuer
    };
  } else {
    credential.issuer = issuer;
  }

  // there may be N-many credential status writers; one for each status of
  // for the same credential
  const credentialStatusWriters = [];

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

    // create VC status writer(s)
    const {issuer, suite} = await _getIssuerAndSuite({config, suiteName});
    const slcsBaseUrl = config.id + bedrock.config['vc-issuer'].routes.slcs;
    credentialStatusWriters.push(new CredentialStatusWriter({
      slcsBaseUrl,
      documentLoader,
      documentStore,
      issuer,
      statusListConfig: {type, ...statusListConfig},
      suite
    }));
  }

  let issued = false;
  let verifiableCredential;
  while(!issued) {
    // write any credential status(es)
    await _writeCredentialStatuses({credentialStatusWriters, credential});

    // issue VC
    verifiableCredential = await _issue({credential, documentLoader, suite});

    // if no credential status writer(s), do not store VC; note that this means
    // that VC IDs will not be checked for duplicates, this will be the
    // responsibility of clients, etc.
    if(credentialStatusWriters.length === 0) {
      issued = true;
      break;
    }

    try {
      // store issued VC, may throw on duplicate credential status(es) which
      // can be ignored and issuance can be reattempted with new status(es)
      await edvClient.insert({
        doc: {
          id: await edvClient.generateId(),
          content: verifiableCredential,
          // include `meta.type` as a non-user input type to validate against
          meta: {type: 'VerifiableCredential'}
        }
      });
      issued = true;
    } catch(e) {
      if(e.name === 'DuplicateError') {
        // if duplicate error was caused by a duplicate credential ID, it is
        // non-recoverable
        if(await edvClient.count({
          equals: {'content.id': credential.id}
        }) !== 0) {
          throw new BedrockError(
            'Could not issue credential; duplicate credential ID.',
            'DuplicateError', {
              public: true,
              httpStatusCode: 409
            });
        }

        // if caused by a duplicate credential status ID, continue to try again
        if(await _hasDuplicateCredentialStatus(
          {credentialStatusWriters, credential})) {
          continue;
        }
      }

      // error not caused by a duplicate credential status ID, throw it
      throw e;
    }
  }

  // finish any status writers
  _finishCredentialStatusWriters({credentialStatusWriters});

  return verifiableCredential;
}

export async function publishSlc({id, config} = {}) {
  assert.string(id, 'id');
  assert.object(config, 'config');

  // do not use cache to ensure latest doc is published
  const documentStore = await _getDocumentStore({config});
  const slcDoc = await documentStore.get({id, useCache: false});
  const {content: credential, meta, sequence} = slcDoc;
  if(!(meta.type === 'VerifiableCredential' &&
    _isStatusListCredential({credential}))) {
    throw new BedrockError(
      `Credential "${id}" is not a supported status list credential.`,
      'DataError', {
        httpStatusCode: 400,
        public: true
      });
  }
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

export async function setStatus({id, config, statusListConfig, status} = {}) {
  assert.string(id, 'id');
  assert.object(config, 'config');
  assert.object(statusListConfig, 'statusListConfig');
  assert.bool(status, 'status');

  const [
    documentLoader,
    documentStore,
    {issuer, suite}
  ] = await Promise.all([
    createDocumentLoader({config}),
    _getDocumentStore({config}),
    _getIssuerAndSuite({config, suiteName: statusListConfig.suiteName})
  ]);

  // get credential
  const {content: credential} = await documentStore.get({id});

  // get SLC document
  const {
    statusListIndex, statusListCredential
  } = getCredentialStatusInfo({credential, statusListConfig});

  // do not use cache to ensure latest doc is retrieved
  let slcDoc = await documentStore.get(
    {id: statusListCredential, useCache: false});

  // TODO: use `documentStore.upsert` and `mutator` feature
  const {edvClient} = documentStore;

  let slcId;
  let slcUpdated = false;
  while(!slcUpdated) {
    try {
      // check if `credential` status is already set, if so, done
      const slc = slcDoc.content;
      const {credentialSubject: {encodedList}} = slc;
      slcId = slc.id;
      const list = await decodeList({encodedList});
      if(list.getStatus(statusListIndex) === status) {
        slcUpdated = true;
        break;
      }

      // update issuer
      slc.issuer = issuer;

      // use index to set status
      list.setStatus(statusListIndex, status);
      slc.credentialSubject.encodedList = await list.encode();

      // express date without milliseconds
      const now = (new Date()).toJSON();
      slc.issuanceDate = `${now.slice(0, -5)}Z`;
      // TODO: we want to be using `issued` and/or `validFrom`, right?
      //slc.issued = issuanceDate;

      // delete existing proof and reissue SLC VC
      delete slc.proof;
      slcDoc.content = await _issue({credential: slc, documentLoader, suite});

      // update SLC doc
      await edvClient.update({doc: slcDoc});
      slcUpdated = true;
    } catch(e) {
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
      // ignore conflict, read and try again
      slcDoc = await edvClient.get({id: slcDoc.id});
    }
  }

  // publish latest version of SLC for non-authz consumption
  await publishSlc({id: slcId, config});
}

export function getMatchingStatusListConfig({config, credentialStatus} = {}) {
  // FIXME: use helper functions from `vc-revocation-list`/`vc-status-list`
  // once they allow context checks to be skipped?
  const {statusListOptions = []} = config;
  for(const statusListConfig of statusListOptions) {
    // default `type` is `RevocationList2020`
    const {type = 'RevocationList2020', statusPurpose} = statusListConfig;
    if(type === 'RevocationList2020' &&
      credentialStatus.type === 'RevocationList2020Status') {
      return {type, ...statusListConfig};
    }
    if(type === 'StatusList2021' &&
      credentialStatus.type === 'StatusList2021Entry' &&
      credentialStatus.statusPurpose === statusPurpose) {
      return statusListConfig;
    }
  }

  let purposeMessage = '';
  if(credentialStatus.statusPurpose) {
    purposeMessage =
      `with status purpose "${credentialStatus.statusPurpose}" `;
  }

  throw new BedrockError(
    `Credential status type "${credentialStatus.type}" ${purposeMessage}` +
    'is not supported by this issuer instance.', 'NotSupportedError', {
      httpStatusCode: 400,
      public: true
    });
}

async function _getDocumentStore({config}) {
  // ensure indexes are set for VCs
  const {documentStore} = await documentStores.get({config, serviceType});
  const {edvClient} = documentStore;
  edvClient.ensureIndex({
    attribute: ['content.credentialStatus.id'],
    unique: true
  });
  return documentStore;
}

async function _getIssuerAndSuite({
  config, suiteName = config.issueOptions.suiteName
}) {
  // get suite params for issuing a VC
  const {createSuite, referenceId} = getSuiteParams({config, suiteName});

  // get assertion method key to use for signing VCs
  const {serviceAgent} = await serviceAgents.get({serviceType});
  const {
    capabilityAgent, zcaps
  } = await serviceAgents.getEphemeralAgent({config, serviceAgent});
  const invocationSigner = capabilityAgent.getSigner();
  const zcap = zcaps[referenceId];
  const kmsClient = new KmsClient({httpsAgent});
  const assertionMethodKey = await AsymmetricKey.fromCapability(
    {capability: zcap, invocationSigner, kmsClient});

  // get `issuer` ID by getting key's public controller
  let issuer;
  try {
    const {controller} = await didIo.get({url: assertionMethodKey.id});
    issuer = controller;
  } catch(e) {
    throw new BedrockError(
      'Unable to determine credential issuer.', 'AbortError', {
        httpStatusCode: 400,
        public: true
      }, e);
  }
  const suite = createSuite({signer: assertionMethodKey});
  return {issuer, suite};
}

// check if `credential` is some known type of status list credential
function _isStatusListCredential({credential}) {
  // FIXME: check for VC context as well
  if(!(credential['@context'] && Array.isArray(credential['@context']))) {
    return false;
  }
  if(!(credential.type && Array.isArray(credential.type) &&
    credential.type.includes('VerifiableCredential'))) {
    return false;
  }

  for(const type of credential.type) {
    if(type === 'RevocationList2020Credential') {
      // FIXME: check for matching `@context` as well
      return true;
    }
    if(type === 'StatusList2021Credential') {
      // FIXME: check for matching `@context as well
      return true;
    }
  }

  return false;
}

async function _writeCredentialStatuses({credentialStatusWriters, credential}) {
  if(credentialStatusWriters.length === 0) {
    return;
  }

  // code assumes there are only a handful of statuses such that no work queue
  // is required; but ensure all writes finish before continuing since this
  // code can run in a loop and cause overwrite bugs with slow database calls
  const results = await Promise.allSettled(credentialStatusWriters.map(
    writer => writer.write({credential})));
  // throw any errors for failed writes
  for(const {status, reason} of results) {
    if(status === 'rejected') {
      throw reason;
    }
  }
}

async function _hasDuplicateCredentialStatus({
  credentialStatusWriters, credential
}) {
  const results = await Promise.allSettled(
    credentialStatusWriters.map(writer => writer.exists({credential})));
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

function _finishCredentialStatusWriters({credentialStatusWriters}) {
  if(credentialStatusWriters.length === 0) {
    return;
  }

  // do not wait for status writing to complete (this would be an unnecessary
  // performance hit)
  credentialStatusWriters.map(w => w.finish().catch(error => {
    // logger errors for later analysis, but do not throw them; credential
    // status write can be continued later by another process
    logger.error(error.message, {error});
  }));
}

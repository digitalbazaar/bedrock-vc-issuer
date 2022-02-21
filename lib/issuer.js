/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as slcs from './slcs.js';
import assert from 'assert-plus';
import bedrock from 'bedrock';
import {AsymmetricKey, KmsClient} from '@digitalbazaar/webkms-client';
import {CredentialStatusWriter} from './CredentialStatusWriter.js';
import {didIo} from 'bedrock-did-io';
import {documentLoader} from './documentLoader.js';
import {documentStores, serviceAgents} from 'bedrock-service-agent';
import {Ed25519Signature2018} from '@digitalbazaar/ed25519-signature-2018';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {decodeList, getCredentialStatus} from '@digitalbazaar/vc-status-list';
import {
  getCredentialStatus as get2020CredentialStatus
} from 'vc-revocation-list';
import {httpsAgent} from 'bedrock-https-agent';
import vc from '@digitalbazaar/vc';
const {util: {BedrockError}} = require('bedrock');

const serviceType = 'vc-issuer';
const SUPPORTED_SUITES = new Map([
  ['Ed25519Signature2020', {
    keyType: 'ed25519', SuiteClass: Ed25519Signature2020
  }],
  ['Ed25519Signature2018', {
    keyType: 'ed25519', SuiteClass: Ed25519Signature2018
  }]
]);

// exported for testing purposes
export const _CredentialStatusWriter = CredentialStatusWriter;

export function getSuiteParams({config, suiteName}) {
  // ensure suite is supported
  const suiteInfo = SUPPORTED_SUITES.get(suiteName);
  if(!suiteInfo) {
    throw new Error(`Unsupported suite "${suiteName}".`);
  }

  // get zcap to use to invoke assertion method key
  const {keyType, SuiteClass} = suiteInfo;
  const referenceId = `assertionMethod:${keyType}`;
  const zcap = config.zcaps[referenceId];
  if(!zcap) {
    throw new Error(
      `No capability available to sign using suite "${suiteName}".`);
  }

  return {zcap, SuiteClass};
}

export async function issue({credential, config, suiteName} = {}) {
  assert.object(credential, 'credential');
  assert.object(config, 'config');
  assert.optionalString(suiteName, 'suiteName');

  const [documentStore, {issuer, suite}] = await Promise.all([
    _getDocumentStore,
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

  // FIXME: see if `credential` has `credentialStatus` set, and if so, see
  // if the `credential['@context']` has a supported status `@context` and
  // if the specified type is supported; map to `statusType`
  const useRevocationList2020 = true;
  const statusType = 'revoked';

  // if revocation list config option is set, create a VC status writer
  let credentialStatusWriter;
  if(useRevocationList2020) {
    // FIXME: remove this and just assert it instead
    credential['@context'].push('https://w3id.org/vc-revocation-list-2020/v1');
    // assertRevocationList2020Context({credential});
    const {issuer, suite} = await _getSLCIssuerAndSuite({config, statusType});
    const slcsBaseUrl = config.id + bedrock.config['vc-issuer'].routes.slcs;
    credentialStatusWriter = new CredentialStatusWriter({
      slcsBaseUrl,
      documentStore,
      issuer,
      suite
    });
  }

  let issued = false;
  let verifiableCredential;
  // FIXME: implement timeout
  while(!issued) {
    if(credentialStatusWriter) {
      // write new credential status on credential
      await credentialStatusWriter.write({credential});
    }

    // issue VC
    verifiableCredential = await _issue({credential, suite});

    try {
      // store issued VC, may throw on duplicate credential status which
      // can be ignored and issuance can be reattempted with a new status
      await edvClient.insert({
        id: await edvClient.generateId(),
        content: verifiableCredential,
        // include `meta.type` as a non-user input type to validate against
        meta: {type: 'VerifiableCredential', credentialStatus: []}
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
        // if caused by a duplicate credential status ID, continue and try
        // again
        if(credentialStatusWriter &&
          await credentialStatusWriter.exists({credential})) {
          continue;
        }
      }

      // error not caused by a duplicate credential status ID, throw it
      throw e;
    }
  }

  // finish writer, but do not wait for it to complete, ignoring any errors
  if(credentialStatusWriter) {
    // TODO: log any errors for later analysis
    credentialStatusWriter.finish().catch(() => {});
  }

  return verifiableCredential;
}

export async function publishSlc({id, config} = {}) {
  assert.string(id, 'id');
  assert.object(config, 'config');

  // do not use cache to ensure latest doc is published
  const {documentStore} = await _getDocumentStore({config});
  const slcDoc = await documentStore.get({id, useCache: false});
  const {content: credential, meta, sequence} = slcDoc;
  if(meta.type === 'VerifiableCredential' &&
    _isStatusListCredential({credential})) {
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

export async function setStatus({id, config, statusType, status} = {}) {
  assert.string(id, 'id');
  assert.object(config, 'config');
  assert.string(statusType, 'statusType');
  assert.bool(status, 'status');

  const [
    {documentStore},
    {issuer, suite}
  ] = await Promise.all([
    _getDocumentStore({config}),
    _getSLCIssuerAndSuite({config, statusType})
  ]);

  // get credential document
  let credentialDoc = await documentStore.get({id});
  const {content: credential} = credentialDoc;

  // get SLC document
  const {
    statusListIndex, statusListCredential
  } = _getCredentialStatusInfo({credential, statusType});

  // do not use cache to ensure latest doc is retrieved
  let slcDoc = await documentStore.get(
    {id: statusListCredential, useCache: false});

  // TODO: use `documentStore.upsert` and `mutator` feature
  const {edvClient} = documentStore;

  // FIXME: add timeout
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
      slcDoc.content = await _issue({credential: slc, suite});

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

  // TODO: use `documentStore.upsert` and `mutator` feature

  // mark credential status in its meta
  // FIXME: add timeout
  let hasStatus = credentialDoc.meta.credentialStatus.contains(statusType);
  let credentialUpdated = hasStatus === status;
  while(!credentialUpdated) {
    try {
      const set = new Set(credentialDoc.meta.credentialStatus);
      if(status) {
        set.add(statusType);
      } else {
        set.remove(statusType);
      }
      credentialDoc.meta.credentialStatus = [...set];
      await edvClient.update({doc: credentialDoc});
      credentialUpdated = true;
    } catch(e) {
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
      // ignore conflict, read and try again
      credentialDoc = await edvClient.get({id: credentialDoc.id});
      hasStatus = credentialDoc.meta.credentialStatus.contains(statusType);
      credentialUpdated = hasStatus === status;
    }
  }
}

function _getCredentialStatusInfo({credential, statusType}) {
  let credentialStatus;
  let statusListIndex;
  let statusListCredential;
  if(statusType === 'revoked') {
    // try modern credential status first
    try {
      // FIXME: once passing `statusType` is supported, pass it and call this
      // above instead of within conditional
      credentialStatus = getCredentialStatus({credential});
      statusListIndex = parseInt(credentialStatus.revocationListIndex, 10);
      ({revocationListCredential: statusListCredential} = credentialStatus);
    } catch(e) {}

    // try legacy credential status
    credentialStatus = get2020CredentialStatus({credential});
    statusListIndex = parseInt(credentialStatus.revocationListIndex, 10);
    ({revocationListCredential: statusListCredential} = credentialStatus);
  } else {
    throw new Error(`Unsupported status type "${statusType}".`);
  }
  return {credentialStatus, statusListIndex, statusListCredential};
}

async function _getDocumentStore({config}) {
  // ensure indexes are set for VCs
  const documentStore = await documentStores.get({config, serviceType});
  const {edvClient} = documentStore;
  edvClient.ensureIndex({attribute: 'meta.credentialStatus'});
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
  const {zcap, SuiteClass} = _getSuiteParams({config, suiteName});

  // get assertion method key to use for signing VCs
  const {serviceAgent} = await serviceAgents.get({serviceType});
  const invocationSigner = await serviceAgents.get({serviceAgent});
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

  const suite = new SuiteClass({signer: assertionMethodKey});
  return {issuer, suite};
}

async function _getSLCIssuerAndSuite({config, statusType}) {
  assert.string(statusType, 'statusType');

  let suiteName;
  const {statusListOptions = []} = config;
  for(const statusListConfig of statusListOptions) {
    if(statusListConfig.statusType === statusType) {
      suiteName = statusListConfig.suiteName;
      break;
    }
  }

  if(!suiteName) {
    throw new Error(`Unsupported status type "${statusType}".`);
  }

  return _getIssuerAndSuite({config, suiteName});
}

async function _issue({credential, suite}) {
  // vc-js.issue may be fixed to not mutate credential
  // see: https://github.com/digitalbazaar/vc-js/issues/76
  credential = {...credential};
  return vc.issue({credential, documentLoader, suite});
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

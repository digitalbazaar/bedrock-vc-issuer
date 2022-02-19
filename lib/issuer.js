/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as slcs from './slcs.js';
import {CredentialStatusWriter} from './CredentialStatusWriter.js';
// FIXME: consider how to also integrate `@digitalbazaar/vc-status-list`
import {
  decodeList,
  getCredentialStatus
} from 'vc-revocation-list';
import {getIssuingInterfaces, issue as _issue} from './helpers.js';

const {util: {BedrockError}} = require('bedrock');

// exported for testing purposes
export const _CredentialStatusWriter = CredentialStatusWriter;

export async function issue({credential, config}) {
  // FIXME: `suiteName` missing; should SLC always be issued with the same
  // suite ... regardless of what the VC is being issued as? need to make
  // sure it doesn't keep changing which suite is used based on the VC
  // presently being issued
  const {documentStore, issuer, suite} = await getIssuingInterfaces({config});
  const {edvClient} = documentStore;

  if(typeof credential.issuer === 'object') {
    credential.issuer = {
      ...credential.issuer,
      id: issuer
    };
  } else {
    credential.issuer = issuer;
  }

  // TODO: get revocation list option from issuer service object config
  // or elsewhere (possibly parameterized)
  const useRevocationList2020 = true;

  // if revocation list config option is set, create a VC status writer
  let credentialStatusWriter;
  if(useRevocationList2020) {
    // FIXME: remove this and just assert it instead
    credential['@context'].push('https://w3id.org/vc-revocation-list-2020/v1');
    // assertRevocationList2020Context({credential});
    credentialStatusWriter = new CredentialStatusWriter({
      // Note: This must match the value used in `http.js`
      // TODO: use a config value so it comes from one place
      slcBaseUrl: `${config.id}/slc`,
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
    verifiableCredential = await issue({credential, suite});

    try {
      // store issued VC, may throw on duplicate credential status which
      // can be ignored and issuance can be reattempted with a new status
      await edvClient.insert({
        id: await edvClient.generateId(),
        content: verifiableCredential, meta: {}
      });
      issued = true;
    } catch(e) {
      // FIXME: explore simplifying -- can `e.name === 'DuplicateError'` be
      // used to help reduce any extra calls here?
      if(!(e.name === 'InvalidStateError' && credentialStatusWriter &&
        await credentialStatusWriter.exists({credential}))) {
        // first see if it was caused by a duplicate credential ID
        // throw DuplicateError error -- otherwise throw whatever the error is.
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
        // error not caused by a duplicate credential status ID, throw it
        throw e;
      }
      // ignore duplicate errors based on credential status and loop
      // to attempt issuance again
    }
  }

  // finish writer, but do not wait for it to complete, ignoring any errors
  if(credentialStatusWriter) {
    // TODO: log any errors for later analysis
    credentialStatusWriter.finish().catch(() => {});
  }

  return verifiableCredential;
}

// FIXME: support other status types
export async function revoke({credentialId, config}) {
  // get interfaces for issuing/revoking VCs
  // FIXME: `suiteName` missing
  const {documentStore, suite} = await getIssuingInterfaces({config});
  const {edvClient} = documentStore;

  // get credential document
  let credentialDoc = await documentStore.get({id: credentialId});
  const {content: credential} = credentialDoc;

  // get SLC document
  const credentialStatus = getCredentialStatus({credential});
  const statusListIndex = parseInt(credentialStatus.revocationListIndex, 10);
  // FIXME: support `statusListCredential`
  const {revocationListCredential} = credentialStatus;

  const {documents: slcDocuments} = await edvClient.find({
    equals: {'content.id': revocationListCredential},
    limit: 1
  });

  if(slcDocuments.length === 0) {
    throw new Error(
      `RevocationListCredential "${revocationListCredential}" not found.`);
  }

  // TODO: use `documentStore.upsert` and `mutator` feature

  // FIXME: add timeout
  let [slcDoc] = slcDocuments;
  let slcId;
  let slcUpdated = false;
  while(!slcUpdated) {
    try {
      // check if `credential` is already revoked, if so, done
      const slcCredential = slcDoc.content;
      const {credentialSubject: {encodedList}} = slcCredential;
      slcId = slcCredential.id;
      const list = await decodeList({encodedList});
      // FIXME: use `getStatus()`
      if(list.isRevoked(statusListIndex)) {
        slcUpdated = true;
        break;
      }

      // update index as revoked and reissue VC
      list.setRevoked(statusListIndex, true);
      slcCredential.credentialSubject.encodedList = await list.encode();
      // express date without milliseconds
      const now = (new Date()).toJSON();
      slcCredential.issuanceDate = `${now.slice(0, -5)}Z`;
      // TODO: we want to be using `issued` and/or `validFrom`, right?
      //slcCredential.issued = issuanceDate;

      // clear existing proof and resign VC
      delete slcCredential.proof;
      slcDoc.content = await _issue({credential: slcCredential, suite});

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

  // mark credential as revoked in its meta
  // FIXME: add timeout
  let credentialUpdated = credentialDoc.meta.revoked;
  while(!credentialUpdated) {
    try {
      credentialDoc.meta.revoked = true;
      await edvClient.update({doc: credentialDoc});
      credentialUpdated = true;
    } catch(e) {
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
      // ignore conflict, read and try again
      credentialDoc = await edvClient.get({id: credentialDoc.id});
      credentialUpdated = credentialDoc.meta.revoked;
    }
  }
}

// FIXME: support other status types
export async function publishSlc({id, config}) {
  // FIXME: `suiteName` missing
  const {documentStore} = await getIssuingInterfaces({config});
  const slcDoc = await documentStore.edvClient.get({id});
  const {content: credential, sequence} = slcDoc;
  // TODO: more fully validate SLC Doc
  if(!(Array.isArray(credential.type) &&
    credential.type.includes('VerifiableCredential') &&
    // FIXME: support other status types
    credential.type.includes('RevocationList2020Credential'))) {
    throw new BedrockError(
      `Credential "${id}" is not a valid RevocationList2020Credential.`,
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

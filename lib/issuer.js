/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config, util: {BedrockError}} = require('bedrock');
const CredentialStatusWriter = require('./CredentialStatusWriter');
const {
  decodeList,
  getCredentialStatus,
  assertRevocationList2020Context
} = require('vc-revocation-list');
const {getIssuingInterfaces, getEdvDocument, issue} = require('./helpers');
const rlcs = require('./rlc');

// load config defaults
require('./config');

// exported for testing purposes
exports._CredentialStatusWriter = CredentialStatusWriter;

exports.issue = async ({credential, profileAgentRecord}) => {
  const {issuer, suite, credentialsCollection, profileAgent} =
    await getIssuingInterfaces({profileAgentRecord});

  if(typeof credential.issuer === 'object') {
    credential.issuer = {
      ...credential.issuer,
      id: issuer
    };
  } else {
    credential.issuer = issuer;
  }

  // TODO: get revocation list option from instance (profile) configuration
  // or elsewhere
  const useRevocationList2020 = true;

  // if revocation list config option is set, create a VC status writer
  let credentialStatusWriter;
  if(useRevocationList2020) {
    assertRevocationList2020Context({credential});
    const instanceId = profileAgentRecord.profileAgent.profile;
    credentialStatusWriter = new CredentialStatusWriter({
      // Note: This must match the value used in `http.js`
      // TODO: use a config value so it comes from one place
      rlcBaseUrl: `${config.server.baseUri}/vc-issuer/instances/` +
        `${encodeURIComponent(instanceId)}/rlc`,
      issuer,
      suite,
      credentialsCollection,
      profileAgent
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
      await credentialsCollection.create(
        {item: verifiableCredential, meta: {}});
      issued = true;
    } catch(e) {
      if(!(e.name === 'InvalidStateError' && credentialStatusWriter &&
        await credentialStatusWriter.exists({credential}))) {
        // first see if it was caused by a duplicate credential ID
        // throw DuplicateError error -- otherwise throw whatever the error is.
        if(await credentialsCollection.countDocuments({
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
};

// TODO: mirror/reuse bedrock-web-vc-issuer `revokeCredential` and
// automatically update RLC that is served as opposed to frontend that
// must hit an additional endpoint
/*exports.revoke = async ({credential, profileAgentRecord}) => {
  // TODO: implement
  // const {issuer, suite, credentialsCollection} =
  //   await getIssuingInterfaces({profileAgentRecord});
};*/

exports.revoke = async ({credentialId, profileAgentRecord}) => {
  // get interfaces for issuing/revoking VCs
  const {suite, credentialsCollection} =
    await getIssuingInterfaces({profileAgentRecord});
  const {edvClient, capability, invocationSigner} = credentialsCollection;

  // get credential document
  const {documents: credentialDocuments} = await edvClient.find({
    equals: {'content.id': credentialId},
    capability,
    invocationSigner
  });
  if(credentialDocuments.length === 0) {
    throw new Error(`Credential "${credentialId}" not found.`);
  }
  let [credentialDoc] = credentialDocuments;
  const {content: credential} = credentialDoc;
  const credentialEdvDoc = await getEdvDocument(
    {id: credentialDoc.id, edvClient, capability, invocationSigner});

  // TODO: support other revocation methods

  // get RLC document
  const credentialStatus = getCredentialStatus({credential});
  const revocationListIndex = parseInt(
    credentialStatus.revocationListIndex, 10);
  const {revocationListCredential} = credentialStatus;

  const {documents: rlcDocuments} = await edvClient.find({
    equals: {'content.id': revocationListCredential},
    capability,
    invocationSigner
  });

  if(rlcDocuments.length === 0) {
    throw new Error(
      `RevocationListCredential "${revocationListCredential}" not found.`);
  }

  // FIXME: add timeout
  let [rlcDoc] = rlcDocuments;
  let rlcId;
  const rlcEdvDoc = await getEdvDocument(
    {id: rlcDoc.id, edvClient, capability, invocationSigner});
  let rlcUpdated = false;
  while(!rlcUpdated) {
    try {
      // check if `credential` is already revoked, if so, done
      const rlcCredential = rlcDoc.content;
      const {credentialSubject: {encodedList}} = rlcCredential;
      rlcId = rlcCredential.id;
      const list = await decodeList({encodedList});
      if(list.isRevoked(revocationListIndex)) {
        rlcUpdated = true;
        break;
      }

      // update index as revoked and reissue VC
      list.setRevoked(revocationListIndex, true);
      rlcCredential.credentialSubject.encodedList = await list.encode();
      // express date without milliseconds
      const now = (new Date()).toJSON();
      rlcCredential.issuanceDate = `${now.substr(0, now.length - 5)}Z`;
      // TODO: we want to be using `issued`, right?
      //rlcCredential.issued = issuanceDate;

      // clear existing proof and resign VC
      delete rlcCredential.proof;
      rlcDoc.content = await issue({credential: rlcCredential, suite});

      // update RLC doc
      await rlcEdvDoc.write({doc: rlcDoc});
      rlcUpdated = true;
    } catch(e) {
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
      // ignore conflict, read and try again
      rlcDoc = await rlcEdvDoc.read();
    }
  }

  // publish latest version of RLC for non-authz consumption
  await exports.publishRlc({id: rlcId, profileAgentRecord});

  // mark credential as revoked in its meta
  // FIXME: add timeout
  let credentialUpdated = credentialDoc.meta.revoked;
  while(!credentialUpdated) {
    try {
      credentialDoc.meta.revoked = true;
      await credentialEdvDoc.write({doc: credentialDoc});
      credentialUpdated = true;
    } catch(e) {
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
      // ignore conflict, read and try again
      credentialDoc = await credentialEdvDoc.read();
      credentialUpdated = credentialDoc.meta.revoked;
    }
  }
};

exports.publishRlc = async ({id, profileAgentRecord}) => {
  const {credentialsCollection} = await getIssuingInterfaces(
    {profileAgentRecord});
  const rlcDoc = await credentialsCollection.get({id});
  const {content: credential, sequence} = rlcDoc;
  // TODO: more fully validate RLC Doc
  if(!(Array.isArray(credential.type) &&
    credential.type.includes('VerifiableCredential') &&
    credential.type.includes('RevocationList2020Credential'))) {
    throw new BedrockError(
      `Credential "${id}" is not a valid RevocationList2020Credential.`,
      'DataError', {
        httpStatusCode: 400,
        public: true
      });
  }
  try {
    // store RLC Doc for public serving
    await rlcs.set({credential, sequence});
  } catch(e) {
    // safe to ignore conflicts, a newer version of the RLC was published
    // than the one that was retrieved
    if(e.name === 'InvalidStateError' || e.name === 'DuplicateError') {
      return;
    }
    throw e;
  }
};

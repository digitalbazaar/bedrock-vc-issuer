/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config, util: {BedrockError}} = require('bedrock');
const CredentialStatusWriter = require('./CredentialStatusWriter');
const {assertRevocationList2020Context} = require('vc-revocation-list');
const {getIssuingInterfaces, issue} = require('./helpers');
const rlcs = require('./rlc');

// load config defaults
require('./config');

exports.issue = async ({credential, profileAgentRecord}) => {
  const {issuer, suite, credentialsCollection, profileAgent} =
    await getIssuingInterfaces({profileAgentRecord});

  credential.issuer = issuer;

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
console.log('credentialStatusWriter set');
  let issued = false;
  let verifiableCredential;
  // FIXME: implement timeout
  while(!issued) {
    if(credentialStatusWriter) {
      // write new credential status on credential
try {
      await credentialStatusWriter.write({credential});
} catch(e) {
  console.error(e);
  throw e;
}
    }
console.log('credentialStatusWriter write');
    // issue VC
    verifiableCredential = await issue({credential, suite});
console.log('issued credential');
    try {
      // store issued VC, may throw on duplicate credential status which
      // can be ignored and issuance can be reattempted with a new status
      await credentialsCollection.create(
        {item: verifiableCredential, meta: {}});
      issued = true;
    } catch(e) {
      if(!(e.name === 'DuplicateError' && credentialStatusWriter &&
        await credentialStatusWriter.exists({credential}))) {
        // not a duplicate error, throw it
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
console.log('returning credential');
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

/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const CredentialStatusWriter = require('./CredentialStatusWriter');
const {assertRevocationList2020Context} = require('vc-revocation-list');
const {getIssuingInterfaces, issue} = require('./helpers');

// load config defaults
require('./config');

exports.issue = async ({credential, profileAgentRecord}) => {
  const {issuer, suite, credentialsCollection} =
    await getIssuingInterfaces({profileAgentRecord});

  credential.issuer = issuer;

  // TODO: if revocation list config option is set...
  const useRevocationList2020 = true;

  let credentialStatusWriter;
  if(useRevocationList2020) {
    assertRevocationList2020Context({credential});
    credentialStatusWriter = new CredentialStatusWriter({
      // FIXME: get HTTPS URL from config
      rlcBaseUrl: 'https://example.com/vc-issuer/revocation',
      issuer,
      suite,
      credentialsCollection
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

  return verifiableCredential;
};

// TODO: mirror/reuse bedrock-web-vc-issuer `revokeCredential`
/*exports.revoke = async ({credential, profileAgentRecord}) => {
  // TODO: implement
  // const {issuer, suite, credentialsCollection} =
  //   await getIssuingInterfaces({profileAgentRecord});
};*/

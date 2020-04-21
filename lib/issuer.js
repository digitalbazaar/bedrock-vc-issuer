/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const axios = require('axios');
const brHttpsAgent = require('bedrock-https-agent');
const didResolver = require('./didResolver');
const {profileAgents} = require('bedrock-profile');
const {documentLoader} = require('bedrock-jsonld-document-loader');
const jsigs = require('jsonld-signatures');
const kms = require('./kms');
const {suites: {Ed25519Signature2018}} = jsigs;
const {
  Hmac,
  KeyAgreementKey,
  KmsClient,
} = require('webkms-client');
const vc = require('vc-js');
const {util: {BedrockError}} = require('bedrock');
const Collection = require('./Collection');
const CredentialStatusWriter = require('./CredentialStatusWriter');
const {EdvClient, EdvDocument} = require('edv-client');

// load config defaults
require('./config');

exports.issue = async ({credential, profileAgentRecord}) => {
  const {profileAgent} = profileAgentRecord;
  const {zcaps: {
    userDocument: userDocZcap,
    userKak: userKakZcap,
  }} = profileAgent;

  const invocationSigner = await profileAgents.getSigner({profileAgentRecord});
  const {httpsAgent} = brHttpsAgent;
  const edvDocument = new EdvDocument({
    capability: userDocZcap,
    client: new EdvClient({httpsAgent}),
    keyAgreementKey: kms.createKak({invocationSigner, zcap: userKakZcap}),
    invocationSigner
  });

  const userDoc = await edvDocument.read();
  const {content: {zcaps: {
    ['key-assertionMethod']: assertionMethodZcap,
    ['credential-edv-documents']: credentialsEdvZcap,
    ['credential-edv-hmac']: credentialsEdvHmacZcap,
    ['credential-edv-kak']: credentialsEdvKakZcap,
  }}} = userDoc;

  if(!(assertionMethodZcap && credentialsEdvZcap && credentialsEdvHmacZcap &&
    credentialsEdvKakZcap)) {
    throw new BedrockError('Permission denied.', 'NotAllowedError', {
      httpStatusCode: 400,
      public: true,
    });
  }
  const {invocationTarget: {verificationMethod}} = assertionMethodZcap;
  const issuerKey = kms.createAsymmetricKey(
    {invocationSigner, zcap: assertionMethodZcap});

  const suite = new Ed25519Signature2018({
    verificationMethod,
    signer: issuerKey
  });

  let issuer;
  try {
    const {document: didDocument} = await didResolver.resolve(
      verificationMethod);
    issuer = didDocument.controller;
    credential.issuer = issuer;
  } catch(e) {
    throw new BedrockError(
      'Unable to determine credential issuer.', 'AbortError', {
        httpStatusCode: 400,
        public: true
      }, e);
  }

  const edvClient = new EdvClient({
    httpsAgent,
    keyResolver: _keyResolver,
    keyAgreementKey: new KeyAgreementKey({
      id: credentialsEdvKakZcap.invocationTarget.id,
      type: credentialsEdvKakZcap.invocationTarget.type,
      capability: credentialsEdvKakZcap,
      invocationSigner,
      kmsClient: new KmsClient({httpsAgent}),
    }),
    hmac: new Hmac({
      id: credentialsEdvHmacZcap.invocationTarget.id,
      type: credentialsEdvHmacZcap.invocationTarget.type,
      capability: credentialsEdvHmacZcap,
      invocationSigner,
      kmsClient: new KmsClient({httpsAgent}),
    })
  });

  edvClient.ensureIndex({attribute: 'content.id', unique: true});
  edvClient.ensureIndex({attribute: 'content.type'});
  edvClient.ensureIndex({attribute: 'meta.revoked'});
  // TODO: need indexes for revocation list VCs

  const credentialsCollection = new Collection({
    type: 'VerifiableCredential',
    capability: credentialsEdvZcap,
    edvClient,
    invocationSigner,
  });

  // TODO: if revocation list config option is set...
  const useRevocationList2020 = true;

  let credentialStatusWriter;
  if(useRevocationList2020) {
    // ...need to create a CredentialStatusWriter, etc. and loop
    // around issuing and writing the VC, see CredentialStatusWriter.js
    credentialStatusWriter = new CredentialStatusWriter({
      // FIXME: get HTTPS URL from config
      rlcBaseUrl: 'https://example.com/vc-issuer/revocation',
      credentialsCollection
    });
    // TODO: add revocation list 2020 context or check for its existence
    // in the VC
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
    verifiableCredential = await vc.issue({credential, documentLoader, suite});

    try {
      // store issued VC, may throw on duplicate credential status which
      // can be ignored and issuance can be reattempted with a new status
      await credentialsCollection.create(
        {item: verifiableCredential, meta: {issuer}});
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

// FIXME: make more restrictive, support `did:key` and `did:v1`
async function _keyResolver({id}) {
  const {httpsAgent} = brHttpsAgent;
  const headers = {Accept: 'application/ld+json, application/json'};
  const response = await axios.get(id, {headers, httpsAgent});
  return response.data;
}

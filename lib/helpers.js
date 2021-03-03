/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const axios = require('axios');
const brHttpsAgent = require('bedrock-https-agent');
const didResolver = require('./didResolver');
const {profileAgents} = require('bedrock-profile');
//const {documentLoader} = require('bedrock-jsonld-document-loader');
const {documentLoader} = require('./documentLoader');
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
const {EdvClient, EdvDocument} = require('edv-client');

// TODO: need a common place for this
const JWE_ALG = 'ECDH-ES+A256KW';

// load config defaults
require('./config');

exports.issue = async ({credential, suite}) => {
  // vc-js.issue may be fixed to not mutate credential
  // see: https://github.com/digitalbazaar/vc-js/issues/76
  credential = {...credential};
  return vc.issue({credential, documentLoader, suite});
};

exports.getIssuingInterfaces = async ({profileAgentRecord}) => {
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
  edvClient.ensureIndex({
    attribute: [
      'content.credentialStatus.id',
      'content.credentialStatus.revocationListIndex'
    ],
    unique: true
  });

  const credentialsCollection = new Collection({
    type: 'VerifiableCredential',
    capability: credentialsEdvZcap,
    edvClient,
    invocationSigner,
  });

  return {issuer, suite, credentialsCollection, profileAgent};
};

exports.getEdvDocument = (
  {id, edvClient, capability, invocationSigner} = {}) => {
  const {keyResolver, keyAgreementKey, hmac} = edvClient;
  const recipients = [{
    header: {kid: keyAgreementKey.id, alg: JWE_ALG}
  }];
  return new EdvDocument({
    id, recipients, keyResolver, keyAgreementKey, hmac,
    capability, invocationSigner, client: edvClient
  });
};

// FIXME: make more restrictive, support `did:key` and `did:v1`
async function _keyResolver({id}) {
  const {httpsAgent} = brHttpsAgent;
  const headers = {Accept: 'application/ld+json, application/json'};
  const response = await axios.get(id, {headers, httpsAgent});
  return response.data;
}

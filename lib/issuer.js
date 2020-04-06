/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brHttpsAgent = require('bedrock-https-agent');
const {profileAgents} = require('bedrock-profile');
const {documentLoader} = require('bedrock-jsonld-document-loader');
const jsigs = require('jsonld-signatures');
const kms = require('./kms');
const {suites: {Ed25519Signature2018}} = jsigs;
const {
  AsymmetricKey,
} = require('webkms-client');
const vc = require('vc-js');
const {util: {BedrockError}} = require('bedrock');
const {EdvClient, EdvDocument} = require('edv-client');

// load config defaults
require('./config');

const instances = exports.instances = require('./instances');
exports.users = require('./users');
exports.capabilitySets = require('./capabilitySets');
//exports.configurations = require('./configurations');

exports.issue = async ({instance, credential}) => {
  // get the capability to sign credentials that was given to the issuer
  // when the instance was setup
  const capability = instance.zcaps.find(
    c => c.referenceId.endsWith('assertionMethod'));

  const {invocationTarget} = capability;
  const {verificationMethod} = invocationTarget;
  const keystoreAgent = await instances.getKeystoreAgent(instance);

  // get the instance's zcap key that is used to invoke the capability
  const zcapInvocationKey = await keystoreAgent.getAsymmetricKey(
    instance.keys.zcapKey);

  // create an interface to use the issuer's key via the capability
  const issuerKey = new AsymmetricKey({
    id: verificationMethod,
    kmsId: invocationTarget.id,
    type: invocationTarget.type,
    capability,
    invocationSigner: zcapInvocationKey,
    kmsClient: keystoreAgent.kmsClient
  });

  // TODO: use issuerKey.type to determine proper suite to use
  const suite = new Ed25519Signature2018({
    verificationMethod,
    signer: issuerKey
  });

  // set issuance date and issue credential
  const date = new Date().toISOString();
  credential.issuanceDate = date.substr(0, date.length - 5) + 'Z';
  const verifiableCredential = await vc.issue({
    credential,
    documentLoader,
    suite
  });

  return verifiableCredential;
};

exports.issueNew = async ({credential, profileAgentRecord}) => {
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
  // FIXME: issue all credentials
  const suite = new Ed25519Signature2018({
    verificationMethod,
    signer: issuerKey
  });

  const verifiableCredential = await vc.issue({
    credential,
    documentLoader,
    suite
  });

  return verifiableCredential;
};

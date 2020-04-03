/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brHttpsAgent = require('bedrock-https-agent');
const {documentLoader} = require('bedrock-jsonld-document-loader');
const jsigs = require('jsonld-signatures');
const {suites: {Ed25519Signature2018}} = jsigs;
const {
  AsymmetricKey,
  CapabilityAgent,
  KeyAgreementKey
} = require('webkms-client');
const vc = require('vc-js');
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

exports.issueNew = async ({profileAgentRecord}) => {
  const {profileAgent, secrets} = profileAgentRecord;
  console.log('SSSSSS', secrets);
  console.log('ZZZZZ', profileAgent.zcaps);
  const {zcaps: {
    userDocument: userDocZcap,
    userKak: userKakZcap,
  }} = profileAgent;
  console.log('CCCCCCCCC', userDocZcap);

  // MAKE CAPABILITY AGENT FROM SEED
  const controller =
    await CapabilityAgent.fromSecret({handle: 'primary', secret: secrets.seed});
  // GET SIGNER FROM CAPABILITY AGENT
  const invocationSigner = controller.getSigner();
  console.log('CONTROLLER', controller);

  // const invocationSigner = await this._getAgentSigner({id: agent.id});
  // const userKakZcap = agent.zcaps['user-edv-kak'];
  const {httpsAgent} = brHttpsAgent;
  const client = new EdvClient({httpsAgent});
  const edvDocument = new EdvDocument({
    capability: userDocZcap,
    client,
    keyAgreementKey: new KeyAgreementKey({
      id: userKakZcap.invocationTarget.id,
      type: userKakZcap.invocationTarget.type,
      capability: userKakZcap,
      invocationSigner
    }),
    invocationSigner
  });

  try {
    const y = await edvDocument.read();
    console.log('USER_DOCUMENT', JSON.stringify(y, null, 2));
  } catch(e) {
    console.log('USER_DOCUEMENT READ ERROR', e.data);
    throw e;
  }
};

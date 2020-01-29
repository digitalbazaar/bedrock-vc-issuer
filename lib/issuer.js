/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brJsonldDocumentLoader = require('bedrock-jsonld-document-loader');
const jsigs = require('jsonld-signatures');
const {suites: {Ed25519Signature2018}} = jsigs;
const {AsymmetricKey} = require('webkms-client');
const vc = require('vc-js');

// load config defaults
require('./config');

const instances = exports.instances = require('./instances');
exports.users = require('./users');
//exports.configurations = require('./configurations');

exports.issue = async ({instance, credential}) => {
  // get the capability to sign credentials that was given to the issuer
  // when the instance was setup
  const capability = instance.zcaps.find(
    c => c.referenceId.endsWith('assertionMethod'));

  const {invocationTarget} = capability;
  const {verificationMethod} = invocationTarget;
  const controllerKey = await instances.getControllerKey(instance);

  // get the instance's zcap key that is used to invoke the capability
  const zcapInvocationKey = await controllerKey.getAsymmetricKey(
    instance.keys.zcapKey);

  // create an interface to use the issuer's key via the capability
  const issuerKey = new AsymmetricKey({
    id: verificationMethod,
    kmsId: invocationTarget.id,
    type: invocationTarget.type,
    capability,
    invocationSigner: zcapInvocationKey,
    kmsClient: controllerKey.kmsClient
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
    documentLoader: brJsonldDocumentLoader.documentLoader,
    suite
  });

  return verifiableCredential;
};

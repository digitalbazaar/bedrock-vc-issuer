/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const jsigs = require('jsonld-signatures');
const {Ed25519Signature2018} = jsigs.suites;
const vc = require('vc-js');

// load config defaults
require('./config');

const instances = exports.instances = require('./instances');
exports.users = require('./users');
//exports.configurations = require('./configurations');

exports.issue = async ({instance, credential}) => {
  const capability = instance.zcaps.find(
    c => c.referenceId.endsWith('assertionMethod'));

  const {invocationTarget} = capability;
  const {verificationMethod} = invocationTarget;
  const controllerKey = await instances.getControllerKey(instance);
  const issuerKey = await controllerKey.getAsymmetricKey({
    id: invocationTarget.id,
    type: invocationTarget.type,
    capability
  });

  // create vcSigner API
  const vcSigner = {
    id: verificationMethod,
    async sign({data}) {
      return issuerKey.sign({data});
    }
  };

  // TODO: use issuerKey.type to determine proper suite to use
  const suite = new Ed25519Signature2018({
    // TODO: do we need to pass this or can we get it from `signer.id`?
    verificationMethod,
    signer: vcSigner
  });

  // set issuance date and issue credential
  const date = new Date().toISOString();
  credential.issuanceDate = date.substr(0, date.length - 5) + 'Z';
  const verifiableCredential = await vc.issue({credential, suite});
  return verifiableCredential;
};

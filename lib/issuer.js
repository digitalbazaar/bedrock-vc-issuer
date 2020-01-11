/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const jsigs = require('jsonld-signatures');
const {Ed25519Signature2018} = jsigs.suites;
const vc = require('vc-js');

// load config defaults
require('./config');

const walletClient = require('./walletClient');

const instances = exports.instances = require('./instances');
//exports.configurations = require('./configurations');

exports.issue = async ({actor, accountId, issuer, credential}) => {
  const {instance} = await instances.get({issuer});
  const capability = instance.capability.find(
    c => c.referenceId === 'assertionMethod');

  // TODO: should be able to auto parse key ID and type from capability
  // within `controllerKey.getAsymmetricKey`
  const {invocationTarget} = capability;
  const controllerKey = await walletClient.getControllerKey(
    {actor, accountId});
  const issuerKey = await controllerKey.getAsymmetricKey({
    id: invocationTarget.id,
    type: invocationTarget.type,
    capability
  });

  // create vcSigner API
  const vcSigner = {
    // TODO: need to be able to get the public key ID associated with the
    // key that will be doing the actual signing; perhaps from
    // `ocap.invocationTarget.referenceId`
    id: issuer + '#8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa',
    async sign({data}) {
      return issuerKey.sign({data});
    }
  };

  // TODO: use issuerKey.type to determine proper suite to use
  const suite = new Ed25519Signature2018({
    // TODO: do we need to pass this or can we get it from `signer.id`?
    verificationMethod:
      issuer + '#8GKQv2nPVqGanxSDygCi8BXrSEJ9Ln6QBhYNWkMCWZDa',
    signer: vcSigner
  });

  // set issuance date and issue credential
  const date = new Date().toISOString();
  credential.issuanceDate = date.substr(0, date.length - 5) + 'Z';
  const verifiableCredential = await vc.issue({credential, suite});
  return verifiableCredential;
};

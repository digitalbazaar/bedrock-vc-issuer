/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

//const _logger = require('./logger');
const bedrock = require('bedrock');
const brZCapStorage = require('bedrock-zcap-storage');
const database = require('bedrock-mongodb');
const jsigs = require('jsonld-signatures');
const {promisify} = require('util');
const {util: {BedrockError}} = bedrock;
const {Ed25519Signature2018} = jsigs.suites;
const vc = require('vc-js');

// load config defaults
require('./config');

const walletClient = require('./walletClient');

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await promisify(database.openCollections)(['vcIssuerRegistration']);

  await promisify(database.createIndexes)([{
    // cover queries by issuer; unique (one registration per issuer)
    collection: 'vcIssuerRegistration',
    fields: {issuer: 1},
    options: {unique: true, background: false}
  }]);
});

exports.issue = async ({actor, accountId, issuer, credential}) => {
  const controllerKey = await walletClient.getControllerKey(
    {actor, accountId});
  const referenceId = `${encodeURIComponent(issuer)}:assertionMethod`;
  const {capability} = await brZCapStorage.zcaps.get(
    {controller: accountId, referenceId});

  // TODO: should be able to auto parse key ID and type from capability
  // within `controllerKey.getAsymmetricKey`
  const {invocationTarget} = capability;
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

const registrations = exports.registrations = {};

registrations.create = async ({actor, registration}) => {
  // TODO: permission check

  // insert the registration and get the updated record
  const now = Date.now();
  const meta = {created: now, updated: now};
  let record = {
    issuer: database.hash(registration.issuer),
    meta,
    registration
  };
  try {
    const result = await database.collections.vcIssuerRegistration.insert(
      record, database.writeOptions);
    record = result.ops[0];
  } catch(e) {
    if(!database.isDuplicateError(e)) {
      throw e;
    }
    throw new BedrockError(
      'Duplicate issuer registration.',
      'DuplicateError', {
        public: true,
        httpStatusCode: 409
      }, e);
  }
};

registrations.get = async ({issuer}) => {
  // Note: no permissions required to get a registration
  const record = await database.collections.vcIssuerRegistration.findOne(
    {issuer: database.hash(issuer)}, {_id: 0, registration: 1});
  if(!record) {
    throw new BedrockError(
      'Issuer registration not found.',
      'NotFoundError',
      {issuer, httpStatusCode: 404, public: true});
  }
  return record;
};

// get all issuer registrations
registrations.getAll = async ({} = {}) => {
  const records = await database.collections.vcIssuerRegistration.find({})
    .toArray();

  return records;
};

const configurations = exports.configurations = {};

configurations.get = async ({registration}) => {
  // Note: no permissions required to get a registration
  const actor = null;
  const {account: accountId, issuer} = registration;
  const referenceId = `${encodeURIComponent(issuer)}:configuration`;
  let capability;
  try {
    const record = await brZCapStorage.zcaps.get(
      {controller: accountId, referenceId});
    capability = record.capability;
  } catch(e) {
    if(e.name === 'NotFoundError') {
      throw new BedrockError(
        'Issuer configuration not found.',
        'NotFoundError',
        {issuer, httpStatusCode: 404, public: true});
    }
    throw e;
  }

  const configuration = await walletClient.storage.get(
    {actor, accountId, capability});
  return {configuration, issuer, account: accountId};
};

// get all issuer configurations by every account
configurations.getAll = async ({} = {}) => {
  // get all registrations
  const records = await database.collections.vcIssuerRegistration.find({})
    .toArray();
  // TODO: could be optimized via `brAccount.getAll`
  return (await Promise.all(records.map(async ({registration}) => {
    try {
      return configurations.get({registration});
    } catch(e) {
      // ignore configuration not found
      if(e.name === 'NotFoundError') {
        return null;
      }
      throw e;
    }
  }))).filter(r => r);
};

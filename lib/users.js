/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const base64url = require('base64url-universal');
const bedrock = require('bedrock');
const brAccount = require('bedrock-account');
const brZCapStorage = require('bedrock-zcap-storage');
const crypto = require('crypto');
const database = require('bedrock-mongodb');
const {promisify} = require('util');
const {util: {BedrockError}} = bedrock;
const https = require('https');
const {ControllerKey, KmsClient} = require('webkms-client');
const {ensureKeystore} = require('./kms');
const {EdvClient} = require('edv-client');
const {Ed25519KeyPair} = require('crypto-ld');
const {delegateCapabilities} = require('./zcaps');
const Collection = require('./Collection');
const instances = require('instances');

// load config defaults
require('./config');

// claim a user by associating it with an account and assigning any zcaps
exports.claimUser = async ({instanceId, accountId, token}) => {
  // ensure account exists
  const {account} = await brAccount.get({actor: null, id: accountId});

  // TODO: get user by token
  const users = await Collection.getInstance({type: 'User', instanceId});
  const {content: user, meta} = users.get({token});
  // TODO: check expiration date on `meta.token.expires`

  // claim user with `accountId`
  if(!user.account) {
    user.account = accountId;
  } else if(user.account !== accountId) {
    throw new BedrockError(
      'Permission denied.', 'NotAllowedError', {
        httpStatusCode: 400,
        public: true
      });
  }

  // set zcaps for user
  await _delegateToUser({instanceId, account, user});
};

async function _delegateToUser({instanceId, account, user}) {
  const id = instanceId;
  const {instance} = await instances.get({id});

  // FIXME: update reference IDs and support multiple vaults,
  // for `admin` and `credentials`
  const [store, issue, edvAuthorizations, keyAuthorizations] =
    await Promise.all([
      instances.getCapability(
        {instance, referenceId: `${id}-edv-configuration`}),
      instances.getCapability(
        {instance, referenceId: `${id}-key-assertionMethod`}),
      instances.getCapability(
        {instance, referenceId: `${id}-edv-authorizations`}),
      instances.getCapability(
        {instance, referenceId: `${id}-key-authorizations`})
    ]);

  // get key for enabling zcaps
  const controllerKey = await exports.getControllerKey({id});
  const signer = await controllerKey.getAsymmetricKey(instance.keys.zcapKey);

  // TODO: base this off of bedrock.config
  const httpsAgent = new https.Agent({
    rejectUnauthorized: false
  });
  const edvClient = new EdvClient({httpsAgent});
  const kmsClient = controllerKey.kmsClient;

  // assign zcaps to account
  // TODO: get did:key from account directly instead of generating
  // controller key here
  const {id: invoker} = await ControllerKey.fromSecret(
    {secret: account.controllerKeySeed, handle: account.id});
  // FIXME: compute zcapMap from already created zcaps
  const zcapMap = {
    write: {
      source: store,
      parent: store
    },
    issue: {
      source: issue,
      parent: issue
    },
    kak: {
      source: instance.keys.kak,
      parent: instance.keys.kak
    },
    hmac: {
      source: instance.keys.hmac,
      parent: instance.keys.hmac
    }
  };
  const delegator = invoker;
  const zcaps = await delegateCapabilities({
    instance, controllerKey, invoker, delegator, zcapMap
  });

  // add zcaps to storage
  for(const referenceId in zcaps) {
    const capability = zcaps[referenceId];
    // TODO: handle case where zcap already exists
    await brZCapStorage.zcaps.insert(
      {controller: account.id, referenceId, capability});
    // enable zcap
    if(referenceId.includes('-edv-')) {
      await edvClient.enableCapability({
        capabilityToEnable: capability,
        capability: edvAuthorizations,
        invocationSigner: signer
      });
    } else if(referenceId.includes('-key-')) {
      // update remote KMS
      await kmsClient.enableCapability({
        capabilityToEnable: capability,
        capability: keyAuthorizations,
        invocationSigner: signer
      });
    } else {
      // update local KMS
      await kmsClient.enableCapability({
        capabilityToEnable: capability,
        invocationSigner: controllerKey
      });
    }
  }
}

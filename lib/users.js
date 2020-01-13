/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brAccount = require('bedrock-account');
const brHttpsAgent = require('bedrock-https-agent');
const brZCapStorage = require('bedrock-zcap-storage');
const {util: {BedrockError}} = bedrock;
const {ControllerKey} = require('webkms-client');
const {EdvClient} = require('edv-client');
const {delegateCapabilities, verifyPartialDelegation} = require('./zcaps');
const Collection = require('./Collection');
const instances = require('./instances');

// load config defaults
require('./config');

// claim a user by associating it with an account and assigning any zcaps
exports.claim = async ({instanceId, accountId, token}) => {
  // ensure account exists
  const {account} = await brAccount.get({actor: null, id: accountId});

  // get user by token
  const users = await Collection.getInstance(
    {type: 'User', instance: instanceId});
  const {content: user, meta} = await users.get({token});
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

  // update user
  await users.update({item: user});

  // set zcaps for user
  await _delegateToUser({instanceId, account, user});
};

exports.get = async ({instanceId, id, token}) => {
  const users = await Collection.getInstance(
    {type: 'User', instance: instanceId});
  return await users.get({id, token});
};

async function _delegateToUser({instanceId, account, user}) {
  const {zcaps: userZcaps = []} = user;
  if(userZcaps.length === 0) {
    // nothing to do, no zcaps to assign
    return;
  }

  const id = instanceId;
  const {instance} = await instances.get({id});
  const controllerKey = await instances.getControllerKey({id});

  // verify partial delegation for all zcaps in the user before minting
  await Promise.all(userZcaps.map(
    capability => verifyPartialDelegation(
      {controllerKey, instance, capability})));

  // FIXME: consolidate code below with _delegateToControllers in `instances.js`

  // FIXME: update reference IDs and support multiple vaults,
  // for `admin` and `credentials`
  const refs = {
    store: `${id}-edv-configuration`,
    issue: `${id}-key-assertionMethod`,
    kak: `${id}-kak`,
    hmac: `${id}-hmac`,
    edvAuthorizations: `${id}-edv-authorizations`,
    kmsAuthorizations: `${id}-key-authorizations`
  };
  const [store, issue, edvAuthorizations, keyAuthorizations] =
    await Promise.all([
      instances.getCapability({instance, referenceId: refs.store}),
      instances.getCapability({instance, referenceId: refs.issue}),
      instances.getCapability({instance, referenceId: refs.edvAuthorizations}),
      instances.getCapability({instance, referenceId: refs.keyAuthorizations})
    ]);

  // assign zcaps to account
  // TODO: get did:key from account directly instead of generating
  // controller key here
  const {id: invoker} = await ControllerKey.fromSecret(
    {secret: account.controllerKeySeed, handle: account.id});
  // compute `zcapMap` from user zcaps
  const zcapMap = {};
  for(const capability of userZcaps) {
    const {referenceId} = capability;
    let {allowedAction} = capability;
    if(allowedAction && !Array.isArray(allowedAction)) {
      allowedAction = [allowedAction];
    }
    if(referenceId === refs.store) {
      if(!allowedAction || allowedAction.includes('write')) {
        zcapMap.write = store;
      } else {
        zcapMap.read = store;
      }
    } else if(referenceId === refs.issue) {
      if(!allowedAction || allowedAction.includes('sign')) {
        zcapMap.issue = issue;
      }
    } else if(referenceId === refs.kak) {
      zcapMap.kak = instance.keys.kak;
    } else if(referenceId === refs.hmac) {
      zcapMap.hmac = instance.keys.hmac;
    } else {
      // other delegations are prohibited
      throw new BedrockError(
        'Permission denied.', 'NotAllowedError', {
          httpStatusCode: 400,
          public: true
        });
    }
  }
  const delegator = invoker;
  const zcaps = await delegateCapabilities({
    instance, controllerKey, invoker, delegator, zcapMap
  });

  const {httpsAgent} = brHttpsAgent;
  const edvClient = new EdvClient({httpsAgent});
  const kmsClient = controllerKey.kmsClient;
  const signer = await controllerKey.getAsymmetricKey(instance.keys.zcapKey);

  // add zcaps to storage and enable them
  for(const referenceId in zcaps) {
    // TODO: better handle case where zcap already exists
    const capability = zcaps[referenceId];
    try {
      await brZCapStorage.zcaps.insert({
        controller: account.id, referenceId, capability
      });
    } catch(e) {
      // ignore duplicates
      if(e.name === 'DuplicateError') {
        continue;
      }
      throw e;
    }

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

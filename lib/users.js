/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brAccount = require('bedrock-account');
const capabilitySets = require('./capabilitySets');
const instances = require('./instances');
const {util: {BedrockError}} = bedrock;
const {ControllerKey} = require('webkms-client');
const Collection = require('./Collection');

// load config defaults
require('./config');

// create an admin user, as needed, by associating it with an account and
// assigning all zcaps
exports.upsertAdmin = async ({instanceId, accountId}) => {
  // ensure account exists
  const {account} = await brAccount.get({actor: null, id: accountId});

  /* Note: It is possible for an existing *unclaimed* "user" with the same
  email address to exist in a degenerate case. This code will upsert another
  user that *is* claimed by the given account. An admin should be able to
  differentiate this existing user from the newly generated and claimed user
  via a user interface, allowing them to delete the existing unclaimed one. */

  // get user by token, upserting as needed
  const users = await Collection.getInstance(
    {type: 'User', instance: instanceId});
  let doc;
  while(!doc) {
    doc = await users.get({token: accountId});
    if(!doc) {
      const item = {
        id: bedrock.util.uuid(),
        type: 'User',
        name: '',
        email: account.email,
        capabilities: ['Read', 'Issue', 'Revoke'],
        authorizedDate: (new Date()).toISOString()
      };
      const meta = {token: {id: accountId}};
      await users.create({item, meta});
    }
  }

  // ensure full capabilities are set
  const {content: user} = doc;
  if(!(user.capabilities.includes('Read') &&
    user.capabilities.includes('Issue') &&
    user.capabilities.includes('Revoke'))) {
    user.capabilities = ['Read', 'Issue', 'Revoke'];
    await users.update({item: user});
  }

  // claim user
  await exports.claim(
    {instanceId, accountId, token: accountId, verifyDelegation: false});
};

// create all admin users for an instance, as needed
exports.upsertAdmins = async ({instanceId}) => {
  const {instance} = await instances.get({id: instanceId});
  let {controller} = instance;
  if(!Array.isArray(controller)) {
    controller = [controller];
  }
  await Promise.all(
    controller.map(accountId => exports.upsertAdmin({instanceId, accountId})));
};

// claim a user by associating it with an account and assigning any zcaps
exports.claim = async ({
  instanceId, accountId, token, verifyDelegation = true
}) => {
  // ensure account exists
  const {account} = await brAccount.get({actor: null, id: accountId});

  // get user by token
  const {instance} = await instances.get({id: instanceId});
  const controllerKey = await instances.getControllerKey(
    {id: instanceId});
  const users = await Collection.getInstance({type: 'User', instance});
  const {content: user, meta} = await users.get({token});
  if('expires' in meta.token) {
    // TODO: check expiration date on `meta.token.expires`
  }

  // claim user with `accountId`
  if(!user.account) {
    user.account = accountId;
    // overwrite token with account ID to allow indexing by account ID
    meta.token = {id: accountId};
    // update user
    await users.update({item: user, meta});
  } else if(user.account !== accountId) {
    throw new BedrockError(
      'Permission denied.', 'NotAllowedError', {
        httpStatusCode: 400,
        public: true
      });
  }

  // delegate zcaps for user to user's account's did:key
  await _delegateToUserAccount(
    {instance, controllerKey, account, user, verifyDelegation});
};

// update the capability set associated with a user
exports.updateCapabilitySet = async ({instanceId, controller, userId}) => {
  // only permit controller to update capability set
  const {instance} = await instances.get({id: instanceId});
  let {controller: controllers} = instance;
  if(!Array.isArray(controllers)) {
    controllers = [controllers];
  }
  if(!controllers.includes(controller)) {
    throw new BedrockError(
      'Permission denied.',
      'NotAllowedError', {httpStatusCode: 400, public: true});
  }

  // get user
  const controllerKey = await instances.getControllerKey(
    {id: instanceId});
  const users = await Collection.getInstance({type: 'User', instance});
  const {content: user} = await users.get({id: userId});

  if(!user.account) {
    // user not yet claimed, nothing to update
    return;
  }

  // delegate zcaps for user to user's account's did:key
  const {account: accountId} = user;
  const {account} = await brAccount.get({actor: null, id: accountId});
  await _delegateToUserAccount({instance, controllerKey, account, user});
};

// get a user by ID or unique token
exports.get = async ({instanceId, id, token}) => {
  const users = await Collection.getInstance(
    {type: 'User', instance: instanceId});
  return await users.get({id, token});
};

// delegate zcaps associated with a "user" to its account's did:key
async function _delegateToUserAccount({
  instance, controllerKey, account, user, verifyDelegation = true
}) {
  const {zcaps: userZcaps = []} = user;
  if(userZcaps.length === 0) {
    // nothing to do, no zcaps to assign
    return;
  }

  // verify partial delegation for all zcaps in the user before minting
  if(!verifyDelegation) {
    await Promise.all(userZcaps.map(
      capability => exports.verifyPartialDelegation(
        {controllerKey, instance, capability})));
  }

  // FIXME: update reference IDs and support multiple vaults,
  // for `admin` and `credentials`
  const {instanceId} = instance;
  const refs = {
    store: `${instanceId}-edv-configuration`,
    issue: `${instanceId}-key-assertionMethod`,
    kak: `${instanceId}-kak`,
    hmac: `${instanceId}-hmac`
  };
  const store = instance.zcaps.find(
    c => c.referenceId === refs.store);
  const issue = instance.zcaps.find(
    c => c.referenceId === refs.issue);

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
  const zcaps = await exports.delegateCapabilities({
    instance, controllerKey, invoker, delegator, zcapMap
  });

  // create or update a capability set for the user
  const capabilitySet = {
    sequence: 0,
    instance: instance.id,
    account: account.id,
    user: user.id,
    zcaps
  };
  try {
    await capabilitySet.create({capabilitySet});
    return;
  } catch(e) {
    if(e.name !== 'DuplicateError') {
      throw e;
    }
  }

  // capability set already exists, update it
  const {capabilitySet: oldSet} = await capabilitySets.get(
    {instanceId: instance.id, userId: user.id});
  capabilitySet.sequence = oldSet.sequence + 1;
  await capabilitySets.update({capabilitySet});
}

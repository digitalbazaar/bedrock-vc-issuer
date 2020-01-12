/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// load config defaults
require('./config');

const instances = require('./instances');
// FIXME: use `Collection` instead
const walletClient = require('./walletClient');

// get an issuer's configuration based via its instance
exports.get = async ({instance}) => {
  // Note: no permissions required to get a instance
  const actor = null;
  const {controller: accountId, issuer, configId: id} = instance;
  const capability = instance.capability.find(
    c => c.referenceId === 'configuration');
  const configuration = await walletClient.storage.get(
    {actor, accountId, id, capability});
  return {configuration, issuer, account: accountId};
};

// get all issuer configurations in the system
exports.getAll = async ({} = {}) => {
  // get all instances
  const records = await instances.getAll();
  // TODO: could be optimized via `brAccount.getAll`
  return (await Promise.all(records.map(async ({instance}) => {
    try {
      return exports.get({instance});
    } catch(e) {
      // ignore configuration not found
      if(e.name === 'NotFoundError') {
        return null;
      }
      throw e;
    }
  }))).filter(r => r);
};

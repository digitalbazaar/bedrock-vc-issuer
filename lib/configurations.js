/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// load config defaults
require('./config');

const registrations = require('./registrations');
const walletClient = require('./walletClient');

// get an issuer's configuration based via its registration
exports.get = async ({registration}) => {
  // Note: no permissions required to get a registration
  const actor = null;
  const {controller: accountId, issuer} = registration;
  const capability = registration.capability.find(
    c => c.referenceId === 'configuration');
  const configuration = await walletClient.storage.get(
    {actor, accountId, capability});
  return {configuration, issuer, account: accountId};
};

// get all issuer configurations in the system
exports.getAll = async ({} = {}) => {
  // get all registrations
  const records = await registrations.getAll();
  // TODO: could be optimized via `brAccount.getAll`
  return (await Promise.all(records.map(async ({registration}) => {
    try {
      return exports.get({registration});
    } catch(e) {
      // ignore configuration not found
      if(e.name === 'NotFoundError') {
        return null;
      }
      throw e;
    }
  }))).filter(r => r);
};

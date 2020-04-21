/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const assert = require('assert-plus');
const {asyncHandler} = require('bedrock-express');
const authorization = require('auth-header');
const base64url = require('base64url-universal');
const bedrock = require('bedrock');
const brAccount = require('bedrock-account');
const crypto = require('crypto');
const {validate} = require('bedrock-validation');
const {config, util: {uuid, BedrockError}} = bedrock;
const {promisify} = require('util');
const {profileAgents} = require('bedrock-profile');
const {
  optionallyAuthenticated
} = require('bedrock-passport');

const vcIssuer = require('./issuer');
const rlcs = require('./rlc');

bedrock.events.on('bedrock-express.configure.routes', app => {
  //const cfg = config['bedrock-vc-issuer'];
  const cfg = {
    routes: {
      authenticate: '/vc-issuer/authenticate',
      // FIXME: should be exposed per instance
      //issueCredential: '/vc-issuer/instances/:instanceId/credentials'
      issueCredential: '/vc-issuer/issue',
      // Note: These must match the `rlcBaseUrl` used in `issuer.js`
      // TODO: use a config value so it comes from one place
      publishRlc: '/vc-issuer/instances/:instanceId/rlc/:rlcId/publish',
      rlc: '/vc-issuer/instances/:instanceId/rlc/:rlcId'
    }
  };
  const {routes} = cfg;

  app.post(routes.authenticate,
    validate({body: 'vc-issuer.login'}),
    asyncHandler(async (req, res) => {
      const {body: {presentation}} = req;
      // extract the DID from the presentation
      const {holder: controller} = presentation;
      // the holder should map to the controller of an account.
      const query = {'account.controller': controller};
      let {actor = null} = req.user || {};
      let [record] = await brAccount.getAll({actor, query});
      while(!record) {
        try {
          record = await brAccount.insert({
            actor,
            account: {
              id: `urn:uuid:${uuid()}`,
              controller,
              // add seed to account so a capability agent can be used
              capabilityAgentSeed: base64url.encode(crypto.randomBytes(32)),
            },
            meta: {
              sysResourceRole: [{
                sysRole: 'account.registered'
              }]
            }
          });
        } catch(e) {
          if(e.name !== 'DuplicateError') {
            throw e;
          }
          // It is possible for concurrent requests
          // to result in 2 inserts with the same controller.
          // That will result in a duplicate account
          // so just return the first account created
          // for a controller.
          [record] = await brAccount.getAll({actor, query});
        }
      }
      const {account} = record;
      actor = await brAccount.getCapabilities({id: account.id});
      const user = {account, actor};

      const login = promisify(req.logIn).bind(req);
      // if login fails, an error will be thrown
      await login(user);

      res.json(account);
    })
  );

  // issue a VC if the posted data meets business rules, this must include
  // verifying a VP included in the posted data
  app.post(
    routes.issueCredential,
    // TODO: validate body
    asyncHandler(async (req, res) => {
      let token;
      try {
        // parse throws if the authorization header is missing
        const auth = authorization.parse(req.get('authorization'));
        if(!(auth.scheme === 'Bearer' && auth.token)) {
          throw new Error('NotAllowedError');
        }
        ({token} = auth);
      } catch(e) {
        throw new BedrockError(
          'Missing or invalid "authorization" header.', 'NotAllowedError', {
            httpStatusCode: 400,
            public: true,
          });
      }

      const {body: {credential}} = req;
      assert.object(credential, 'credential');
      const profileAgentRecord = await profileAgents.getByToken(
        {token, includeSecrets: true});
try{
      const verifiableCredential = await vcIssuer.issue(
        {credential, profileAgentRecord});
} catch(e) {
console.error(e);
}
      res.json({verifiableCredential});
    }));

  // pull latest RLC from EDV storage for an instance and publish it
  app.post(
    routes.publishRlc,
    // TODO: also accept bearer token to identify profile agent in the future
    optionallyAuthenticated,
    // TODO: validate body {profileAgent?}
    asyncHandler(async (req, res) => {
      let profileAgentRecord;
      if(req.isAuthenticated()) {
        profileAgentRecord = await profileAgents.get(
          {id: req.body.profileAgent, includeSecrets: true});
      } else {
        // Note: While this is a permitted action, token-based profile agents
        // should be able to hit a `revoke` endpoint in the future that
        // handles revocation entirely, including updating the RLC that is
        // publicly served. Additional work is required to simplify/unify/clean
        // up these APIs moving forward.
        let token;
        try {
          // parse throws if the authorization header is missing
          const auth = authorization.parse(req.get('authorization'));
          if(!(auth.scheme === 'Bearer' && auth.token)) {
            throw new Error('NotAllowedError');
          }
          ({token} = auth);
        } catch(e) {
          throw new BedrockError(
            'Missing or invalid "authorization" header.', 'NotAllowedError', {
              httpStatusCode: 400,
              public: true
            });
        }
        profileAgentRecord = await profileAgents.getByToken(
          {token, includeSecrets: true});
      }

      // ensure profile claimed by account
      if(profileAgentRecord.profileAgent.account !== req.user.account.id) {
        throw new BedrockError(
          'Permission denied.', 'NotAllowedError', {
            httpStatusCode: 400,
            public: true
          });
      }

      // ensure profile agent matches instance
      const {instanceId} = req.params;
      if(instanceId !== profileAgentRecord.profileAgent.profile) {
        throw new BedrockError(
          'Profile agent does not match issuer instance.', 'NotAllowedError', {
            httpStatusCode: 400,
            public: true
          });
      }

      // build full RLC ID
      const {rlcId} = req.params;
      const id =
        `${config.server.baseUri}/vc-issuer/instances/` +
        `${encodeURIComponent(instanceId)}/rlc/${encodeURIComponent(rlcId)}`;
      await vcIssuer.publishRlc({id, profileAgentRecord});
      res.sendStatus(204);
    }));

  // get latest published RLC, no-authz required
  app.get(
    routes.rlc,
    asyncHandler(async (req, res) => {
      // build full RLC ID
      const {instanceId, rlcId} = req.params;
      const id =
        `${config.server.baseUri}/vc-issuer/instances/` +
        `${encodeURIComponent(instanceId)}/rlc/${encodeURIComponent(rlcId)}`;
      const record = await rlcs.get({id});
      res.json(record.credential);
    }));
});

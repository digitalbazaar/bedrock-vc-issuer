/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const base64url = require('base64url-universal');
const bedrock = require('bedrock');
const brAccount = require('bedrock-account');
const crypto = require('crypto');
//const {config} = bedrock;
const {ensureAuthenticated} = require('bedrock-passport');
const logger = require('./logger');
const {validate} = require('bedrock-validation');
const {util: {uuid, BedrockError}} = bedrock;
const {promisify} = require('util');

const vcIssuer = require('./issuer');

bedrock.events.on('bedrock-express.configure.routes', app => {
  //const cfg = config['bedrock-vc-issuer'];
  const cfg = {
    routes: {
      authenticate: '/vc-issuer/authenticate',
      instances: '/vc-issuer/instances',
      instance: '/vc-issuer/instances/:instanceId',
      instanceIssuer: '/vc-issuer/instances/:instanceId/issuer',
      automatedIssue: '/vc-issuer/issue',
      getUser: '/vc-issuer/instances/:instanceId/users',
      claimUser: '/vc-issuer/instances/:instanceId/claim-user'
    }
  };
  const {routes} = cfg;

  app.post(routes.authenticate,
    validate({body: 'vc-auth.login'}),
    asyncHandler(async (req, res) => {
      const {body: {presentation}} = req;
      // extract the DID from the presentation
      const {holder: controller} = presentation;
      logger.debug('starting login for', {controller});
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
              // add seed to account so a controller key can be used
              controllerKeySeed: base64url.encode(crypto.randomBytes(32)),
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

  // create a new issuer instance
  app.post(
    routes.instances,
    ensureAuthenticated,
    validate('vc-issuer.instancesCreate'),
    asyncHandler(async (req, res) => {
      // verifiable presentation with issuer VC and configuration and
      // assertionMethod zcaps is required to register an issuer
      const {id, name, controller} = req.body;

      // disallow any authenticated user to act as another controller
      const {actor} = req.user;
      if(actor.id !== controller) {
        throw new BedrockError(
          'Permission denied.',
          'NotAllowedError', {httpStatusCode: 400, public: true});
      }

      // create instance
      const instance = {
        id,
        name,
        controller
      };
      const record = await vcIssuer.instances.create({instance});
      res.json(record);
    }));

  // get issuer instances
  app.get(
    routes.instances,
    ensureAuthenticated,
    validate({query: 'vc-issuer.instancesQuery'}),
    asyncHandler(async (req, res) => {
      const {controller} = req.query;
      const records = await vcIssuer.instances.getAll({controller});
      res.json(records);
    }));

  // update an instance's issuer and capabilities (zcaps)
  app.post(
    routes.instanceIssuer,
    ensureAuthenticated,
    // FIXME: validate VP
    asyncHandler(async (req, res) => {
      const {instanceId: id} = req.params;
      logger.debug('UPDATE ISSUER INSTANCE JSON', {body: req.body});

      // verifiable presentation with zcaps for an issuer instance
      const {controller, presentation: vp} = req.body;

      // disallow any authenticated user to act as another controller
      const {actor} = req.user || {};
      if(actor.id !== controller) {
        throw new BedrockError(
          'Permission denied.',
          'NotAllowedError', {httpStatusCode: 400, public: true});
      }

      // TODO: verify VP -- note that this will should be done by another
      // bedrock module that handles challenge strings, etc.

      // TODO: ensure capabilities are for the right thing (prevent some
      // adversary from sending a capability for something else they found
      // elsewhere)

      // VP must be presented by the issuer
      const {holder: issuer, capability} = vp;

      // create instance, including zcaps
      await vcIssuer.instances.setIssuer({
        id, controller, issuer, zcaps: capability
      });
      res.status(204).end();
    }));

  // get a specific issuer instance
  app.get(
    routes.instance,
    ensureAuthenticated,
    asyncHandler(async (req, res) => {
      const {instanceId: id} = req.params;
      const record = await vcIssuer.instances.get({id});
      res.json(record);
    }));

  // delete an issuer instance
  app.delete(
    routes.instance,
    ensureAuthenticated,
    // TODO: validate query, if any
    asyncHandler(async (req, res) => {
      const {instanceId: id} = req.params;
      const {actor} = req.user;
      await vcIssuer.instances.remove({id, controller: actor.id});
      res.status(204).end();
    }));

  // FIXME: remove me
  /*
  // get all issuer configurations
  app.get(
    routes.configurations,
    asyncHandler(async (req, res) => {
      const records = await vcIssuer.configurations.getAll();
      res.json(records);
    }));
  */

  // gets a user
  app.get(
    routes.getUser,
    asyncHandler(async (req, res) => {
      const {instanceId} = req.params;
      const {id, token} = req.query;
      if(id) {
        throw new BedrockError(
          'Querying user by "id" is not allowed.',
          'NotAllowedError', {httpStatusCode: 400, public: true});
      }
      const user = await vcIssuer.users.get({instanceId, token});
      res.json(user.content);
    }));

  // claim a user
  app.post(
    routes.claimUser,
    ensureAuthenticated,
    validate({body: 'vc-auth.claimUser'}),
    asyncHandler(async (req, res) => {
      const {body, user: {account}} = req;
      const {instanceId, token} = body;
      await vcIssuer.users.claim({instanceId, accountId: account.id, token});
      res.status(204).end();
    }));

  // FIXME: reinstate with new `instance` design
  /*
  // issue a VC if the posted data meets business rules, this must include
  // verifying a VP included in the posted data
  app.post(
    routes.automatedIssue,
    asyncHandler(async (req, res) => {
      // end user must submit the issuer identifier, the flow identifier, the
      // generated credential, and a verifiable presentation with their
      // authentication info
      const {
        issuer,
        flow: flowId,
        credentials,
        presentation
      } = req.body;

      // get instance for issuer
      const {instance} = await vcIssuer.instances.get({issuer});
      const {controller: accountId} = instance;

      // get associated configuration
      const configuration = await vcIssuer.configurations.get({instance});

      // TODO: find flow in `configuration` by `flowId`

      // TODO: verify VP
      // TODO: when verifying the VP, it includes a `challenge` that must be
      // checked against a previously stored value (we could map the user's
      // session ID to the `challenge`... each time we verify a VP we should
      // clear the challenge as it is intended to be a nonce

      // TODO: verify VCs in VP and that they match requirements of `flow`
      const results = await Promise.all(credentials.map(async credential => {
        // FIXME: use real contexts
        credential['@context'] = [
          'https://www.w3.org/2018/credentials/v1',
          'https://www.w3.org/2018/credentials/examples/v1',
          {'@vocab': 'https://example.com#'}
        ];
        // allow automated issuance of a VC
        return vcIssuer.issue({actor: null, accountId, issuer, credential});
      }));
      res.json(results);
    }));
    */
});

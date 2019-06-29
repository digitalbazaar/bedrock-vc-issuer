/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const brPassport = require('bedrock-passport');
//const {config} = bedrock;
const {ensureAuthenticated} = brPassport;
//const {validate} = require('bedrock-validation');
const {util: {BedrockError}} = bedrock;

const vcIssuer = require('./issuer');

bedrock.events.on('bedrock-express.configure.routes', app => {
  //const cfg = config['bedrock-vc-issuer'];
  const cfg = {
    routes: {
      registrations: '/vc-issuer/registrations',
      configurations: '/vc-issuer/configurations',
      automatedIssue: '/vc-issuer/issue'
    }
  };
  const {routes} = cfg;

  // create a new issuer registration
  app.post(
    routes.registrations,
    ensureAuthenticated,
    // TODO: validate VP
    asyncHandler(async (req, res) => {
      // verifiable presentation with issuer VC and configuration and
      // assertionMethod zcaps is required to register an issuer
      const {controller, presentation: vp} = req.body;

      // TODO: consider invoking the `account` as a zcap here ... and add
      // `invoker` and `delegator` to the account to avoid having a permission
      // based model here; automatically add an admin account as an invoker
      // whenever the account is retrieved that can't be removed
      const {actor} = req.user;
      if(actor.id !== controller) {
        throw new BedrockError(
          'Permission denied.',
          'NotAllowedError', {httpStatusCode: 400, public: true});
      }

      // TODO: verify VP and VC therein -- note that this will should be
      // done by another bedrock module that handles challenge strings, etc.

      // TODO: ensure capabilities are for the right thing (prevent some
      // adversary from sending a capability for something else they found
      // elsewhere)

      const {verifiableCredential: [vc], capability} = vp;
      // TODO: ensure subject of VC is `vp.holder`
      const {credentialSubject: {id: issuer}} = vc;

      // create registration, including zcaps
      const registration = {
        controller,
        issuer,
        capability
      };
      const record = await vcIssuer.registrations.create({registration});
      res.json(record);
    }));

  // get one or more issuer registrations
  app.get(
    routes.registrations,
    ensureAuthenticated,
    asyncHandler(async (req, res) => {
      const {issuer, controller} = req.query;
      if(issuer) {
        const record = await vcIssuer.registrations.get({issuer});
        res.json(record);
      } else {
        const records = await vcIssuer.registrations.getAll({controller});
        res.json(records);
      }
    }));

  // delete an issuer registration
  app.delete(
    routes.registrations,
    ensureAuthenticated,
    // TODO: validate query
    asyncHandler(async (req, res) => {
      const {issuer} = req.query;
      if(!issuer) {
        // not permitted to delete all registrations at this time
        throw new BedrockError(
          'Permission denied.',
          'NotAllowedError', {httpStatusCode: 400, public: true});
      }

      // will throw a 404 if registration does not exist
      const {registration} = await vcIssuer.registrations.get({issuer});
      const {controller} = registration;

      // TODO: consider invoking the `account` as a zcap here ... and add
      // `invoker` and `delegator` to the account to avoid having a permission
      // based model here; automatically add an admin account as an invoker
      // whenever the account is retrieved that can't be removed
      const {actor} = req.user;
      if(actor.id !== controller) {
        throw new BedrockError(
          'Permission denied.',
          'NotAllowedError', {httpStatusCode: 400, public: true});
      }
      // TODO: also remove configuration before removing registration?
      await vcIssuer.registrations.remove({issuer});
      res.status(204).end();
    }));

  // get all issuer configurations
  app.get(
    routes.configurations,
    asyncHandler(async (req, res) => {
      const records = await vcIssuer.configurations.getAll();
      res.json(records);
    }));

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

      // get registration for issuer
      const {registration} = await vcIssuer.registrations.get({issuer});
      const {controller: accountId} = registration;

      // get associated configuration
      const configuration = await vcIssuer.configurations.get({registration});

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
});

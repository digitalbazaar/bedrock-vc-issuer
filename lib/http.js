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
    asyncHandler(async (req, res) => {
      const registration = req.body;
      vcIssuer.registrations.create({registration});
      res.status(204).end();
    }));

  // get all issuer registrations
  app.get(
    routes.registrations,
    ensureAuthenticated,
    asyncHandler(async (req, res) => {
      const registrations = await vcIssuer.registrations.getAll();
      res.json(registrations);
    }));

  // get all issuer configurations
  app.get(
    routes.configurations,
    asyncHandler(async (req, res) => {
      const configurations = await vcIssuer.configurations.getAll();
      res.json(configurations);
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
      const {account: accountId} = registration;

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

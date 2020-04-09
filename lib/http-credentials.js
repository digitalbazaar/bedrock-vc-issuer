/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const assert = require('assert-plus');
const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const {profileAgents} = require('bedrock-profile');
const vcIssuer = require('./issuer');
const {util: {BedrockError}} = bedrock;

bedrock.events.on('bedrock-express.configure.routes', app => {
  //const cfg = config['bedrock-vc-issuer'];
  const cfg = {
    routes: {
      instanceIssueCredential: '/credentials/:profileAgentId/issueCredential',
    }
  };
  const {routes} = cfg;

  app.post(
    routes.instanceIssueCredential,
    // TODO: add validation
    asyncHandler(async (req, res) => {
      const {
        credential,
        // TODO: implement options per the spec
        // options,
      } = req.body;

      assert.object(credential, 'credential');

      const {params: {profileAgentId}} = req;

      const profileAgentRecord = await profileAgents.get(
        {id: profileAgentId, includeSecrets: true});

      // minimal check to ensure this is a profile agent associated with
      // an application. Only applications have tokens.
      if(!profileAgentRecord.secrets.token) {
        throw new BedrockError(
          'Permission denied.',
          'NotAllowedError', {httpStatusCode: 400, public: true});
      }

      const verifiableCredential = await vcIssuer.issue(
        {credential, profileAgentRecord});

      res.json({verifiableCredential});
    }));
});

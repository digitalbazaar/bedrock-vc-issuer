/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const assert = require('assert-plus');
const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const {profileAgents} = require('bedrock-profile');
const cors = require('cors');
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

  app.options(routes.instanceIssueCredential, cors());
  app.post(
    routes.instanceIssueCredential,
    cors(),
    // TODO: add validation
    asyncHandler(async (req, res) => {
      const {
        credential,
        options
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
      if(options) {
        const {proofPurpose, assertionMethod, verificationMethod} = options;
        if(proofPurpose && proofPurpose !== 'assertionMethod') {
          throw new BedrockError(
            'Unsupported "proofPurpose.',
            'NotSupportedError', {httpStatusCode: 400, public: true});
        }
        if(assertionMethod && !(assertionMethod.includes('did:key') ||
          (assertionMethod.includes('did:v1')))) {
          throw new BedrockError(
            'Usupported "assertionMethod.',
            'NotSupportedError', {httpStatusCode: 400, public: true});
        }
        if(verificationMethod && !(verificationMethod.includes('did:key') ||
          (verificationMethod.includes('did:v1')))) {
          throw new BedrockError(
            'Unsupported "verificationMethod.',
            'NotSupportedError', {httpStatusCode: 400, public: true});
        }
      }
      try {
        const verifiableCredential = await vcIssuer.issue(
          {credential, profileAgentRecord});
        res.status(201).json(verifiableCredential);
      } catch(e) {
        console.log(e);
        res.status(400).json({error: e.name});
      }
    }));
});

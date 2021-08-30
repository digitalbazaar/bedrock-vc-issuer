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

const SUPPORTED_CREDENTIAL_STATUS_TYPES = ['RevocationList2020Status'];

bedrock.events.on('bedrock-express.configure.routes', app => {
  const basePath = '/credentials/:profileAgentId';

  const cfg = {
    routes: {
      instanceIssueCredential: `${basePath}/issueCredential`,
      instanceUpdateCredentialStatus: `${basePath}/updateCredentialStatus`,
    }
  };
  const {routes} = cfg;

  // issue credential
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
        const {
          proofPurpose, assertionMethod, verificationMethod, credentialStatus
        } = options;
        if(proofPurpose && proofPurpose !== 'assertionMethod') {
          throw new BedrockError(
            'Unsupported "proofPurpose".',
            'DataError', {httpStatusCode: 400, public: true});
        }
        if(assertionMethod && !(assertionMethod.includes('did:key') ||
          (assertionMethod.includes('did:v1')))) {
          throw new BedrockError(
            'Usupported "assertionMethod".',
            'DataError', {httpStatusCode: 400, public: true});
        }
        if(verificationMethod && !(verificationMethod.includes('did:key') ||
          (verificationMethod.includes('did:v1')))) {
          throw new BedrockError(
            'Unsupported "verificationMethod".',
            'DataError', {httpStatusCode: 400, public: true});
        }
        if(credentialStatus &&
          credentialStatus.type &&
          !SUPPORTED_CREDENTIAL_STATUS_TYPES.includes(credentialStatus.type)) {
          throw new BedrockError(
            'Unsupported "credentialStatus".',
            'DataError', {httpStatusCode: 400, public: true});
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

  // update credential status
  app.options(routes.instanceUpdateCredentialStatus, cors());
  app.post(
    routes.instanceUpdateCredentialStatus,
    cors(),
    // TODO: add validation
    asyncHandler(async (req, res) => {
      const {
        credentialId,
        credentialStatus
      } = req.body;

      assert.string(credentialId, 'credentialId');
      assert.arrayOfObject(credentialStatus, 'credentialStatus');

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

      const credentialStatusUpdateMap = new Map();

      SUPPORTED_CREDENTIAL_STATUS_TYPES.forEach(type => {
        const statusUpdates = credentialStatus.filter(cs => cs.type === type);
        credentialStatusUpdateMap.set(type, statusUpdates);
      });

      try {
        // only process RevocationList2020Status update
        for(const type of SUPPORTED_CREDENTIAL_STATUS_TYPES) {
          if(type === 'RevocationList2020Status') {
            // only use the first update found and ignore the rest when
            // updating RevocationList2020
            const [statusUpdate] = credentialStatusUpdateMap.get(type);
            const {status} = statusUpdate;
            await vcIssuer.revoke({
              credentialId, status, profileAgentRecord
            });
          }
        }

        res.status(200).end();
      } catch(e) {
        console.error(e);
        res.status(400).json({error: e.name});
      }
    }));
});

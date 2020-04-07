/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const assert = require('assert-plus');
const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const {documentLoader} = require('./documentLoader');
const vc = require('vc-js');
const {Ed25519KeyPair} = require('crypto-ld');
const {suites: {Ed25519Signature2018}} = require('jsonld-signatures');
const {profileAgents} = require('bedrock-profile');
const vcIssuer = require('./issuer');
const {util: {BedrockError}} = bedrock;

const mockSigningKey = {
  type: 'Ed25519VerificationKey2018',
  // eslint-disable-next-line max-len
  privateKeyBase58: '4m1ybR6T3RSWdD31SUTPpi9THjiMwUhwqEP5W7c5WDgaz5vdWoAirhUkRJUrQYfwHoLFeGWV4RAYHbWBwLfC2qrm',
  publicKeyBase58: '2gui9QRXHkkyiCukDRa6SKEc856CdsxUU2CeL6JR32ER'
};

bedrock.events.on('bedrock-express.configure.routes', app => {
  //const cfg = config['bedrock-vc-issuer'];
  const cfg = {
    routes: {
      issueCredential: '/credentials/issueCredential',
      instanceIssueCredential: '/credentials/:profileAgentId/issueCredential',
    }
  };
  const {routes} = cfg;

  app.post(
    routes.issueCredential,
    // TODO: add validation
    asyncHandler(async (req, res) => {
      const {
        credential,
        // TODO: implement options per the spec
        // options,
      } = req.body;

      const issuerKey = new Ed25519KeyPair(mockSigningKey);
      const fingerprint = issuerKey.fingerprint();
      const verificationMethod = `did:key:${fingerprint}#${fingerprint}`;

      // NOTE: for demonstration purposes the credential.issuer is replaced
      // with the controller of the mock signing key
      credential.issuer = `did:key:${fingerprint}`;

      const verifiableCredential = await vc.issue({
        credential,
        documentLoader,
        suite: new Ed25519Signature2018({
          verificationMethod,
          signer: issuerKey.signer(),
        }),
      });

      res.json(verifiableCredential);
    }));

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

      const verifiableCredential = await vcIssuer.issueNew(
        {credential, profileAgentRecord});

      res.json({verifiableCredential});
    }));
});

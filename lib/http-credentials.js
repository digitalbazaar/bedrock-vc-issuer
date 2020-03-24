/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');

const brJsonldDocumentLoader = require('bedrock-jsonld-document-loader');
const vc = require('vc-js');
const {Ed25519KeyPair} = require('crypto-ld');
const {suites: {Ed25519Signature2018}} = require('jsonld-signatures');

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
    }
  };
  const {routes} = cfg;

  app.post(
    routes.issueCredential,
    // TODO: add validation
    asyncHandler(async (req, res) => {
      const {
        credential,
        // FIXME: what are options used for?
        // options,
      } = req.body;

      const issuerKey = new Ed25519KeyPair(mockSigningKey);
      const fingerprint = issuerKey.fingerprint();
      const verificationMethod = `did:key:${fingerprint}#${fingerprint}`;
      const verifiableCredential = await vc.issue({
        credential,
        documentLoader: brJsonldDocumentLoader.documentLoader,
        suite: new Ed25519Signature2018({
          verificationMethod,
          signer: issuerKey.signer(),
        }),
      });

      res.json(verifiableCredential);
    }));
});

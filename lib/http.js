/*!
 * Copyright (c) 2018-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {metering, middleware} from '@bedrock/service-core';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import cors from 'cors';
import {getDocumentStore} from './helpers.js';
import {issue} from './issuer.js';
import {issueCredentialBody} from '../schemas/bedrock-vc-issuer.js';
import {logger} from './logger.js';
import {createValidateMiddleware as validate} from '@bedrock/validation';

const {util: {BedrockError}} = bedrock;

// FIXME: remove and apply at top-level application
bedrock.events.on('bedrock-express.configure.bodyParser', app => {
  app.use(bodyParser.json({
    // allow json values that are not just objects or arrays
    strict: false,
    limit: '10MB',
    type: ['json', '+json']
  }));
});

export async function addRoutes({app, service} = {}) {
  const {routePrefix} = service;

  const cfg = bedrock.config['vc-issuer'];
  const baseUrl = `${routePrefix}/:localId`;
  const routes = {
    credential: `${baseUrl}${cfg.routes.credentials}/:credentialId`,
    credentialsIssue: `${baseUrl}${cfg.routes.credentialsIssue}`,
    publishSlc: `${baseUrl}${cfg.routes.publishSlc}`,
    publishTerseSlc: `${baseUrl}${cfg.routes.publishTerseSlc}`,
    slc: `${baseUrl}${cfg.routes.slc}`,
    terseSlc: `${baseUrl}${cfg.routes.terseSlc}`
  };

  const getConfigMiddleware = middleware.createGetConfigMiddleware({service});

  /* Note: CORS is used on all endpoints. This is safe because authorization
  uses HTTP signatures + capabilities or OAuth2, not cookies; CSRF is not
  possible. */

  // return a previously issued VC, if it has `credentialStatus`
  app.options(routes.credential, cors());
  app.get(
    routes.credential,
    cors(),
    getConfigMiddleware,
    middleware.authorizeServiceObjectRequest(),
    asyncHandler(async (req, res) => {
      try {
        const {config} = req.serviceObject;
        const {credentialId} = req.params;
        const {edvClient} = await getDocumentStore({config});
        const {documents: [doc]} = await edvClient.find({
          equals: {'meta.credentialId': credentialId}
        });
        if(!doc) {
          throw new BedrockError('Credential not found.', {
            name: 'NotFoundError',
            details: {
              credentialId,
              httpStatusCode: 404,
              public: true
            }
          });
        }
        const {content} = doc;
        res.status(200).json({
          verifiableCredential: content
        });
      } catch(error) {
        logger.error(error.message, {error});
        throw error;
      }

      // meter operation usage
      metering.reportOperationUsage({req});
    }));

  // issue a VC
  app.options(routes.credentialsIssue, cors());
  app.post(
    routes.credentialsIssue,
    cors(),
    validate({bodySchema: issueCredentialBody}),
    getConfigMiddleware,
    middleware.authorizeServiceObjectRequest(),
    asyncHandler(async (req, res) => {
      try {
        const {config} = req.serviceObject;
        const {credential, options} = req.body;
        const {
          verifiableCredential, envelopedVerifiableCredential
        } = await issue({credential, config, options});
        const body = {
          verifiableCredential:
            envelopedVerifiableCredential ?? verifiableCredential
        };
        res.status(201).json(body);
      } catch(error) {
        logger.error(error.message, {error});
        // will be thrown for safe mode violations
        if(error.name === 'jsonld.ValidationError') {
          throw new BedrockError('Invalid credential.', {
            name: 'SyntaxError',
            details: {
              httpStatusCode: 400,
              public: true
            }
          });
        }
        // TODO: handle other possible errors
        // in particular @digitalbazaar/vc throws many simple 'TypeError' and
        // 'Error' errors. Difficult to distinguish them from other errors.

        // default to other layers, likely will be an ISE/500
        throw error;
      }

      // meter operation usage
      metering.reportOperationUsage({req});
    }));
}

/*!
 * Copyright (c) 2018-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {metering, middleware} from '@bedrock/service-core';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import cors from 'cors';
import {issue} from './issuer.js';
import {issueCredentialBody} from '../schemas/bedrock-vc-issuer.js';
import {logger} from './logger.js';
import {createValidateMiddleware as validate} from '@bedrock/validation';

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
    credentialsIssue: `${baseUrl}${cfg.routes.credentialsIssue}`,
    credentialsStatus: `${baseUrl}${cfg.routes.credentialsStatus}`,
    publishSlc: `${baseUrl}${cfg.routes.publishSlc}`,
    publishTerseSlc: `${baseUrl}${cfg.routes.publishTerseSlc}`,
    slc: `${baseUrl}${cfg.routes.slc}`,
    terseSlc: `${baseUrl}${cfg.routes.terseSlc}`
  };

  const getConfigMiddleware = middleware.createGetConfigMiddleware({service});

  /* Note: CORS is used on all endpoints. This is safe because authorization
  uses HTTP signatures + capabilities or OAuth2, not cookies; CSRF is not
  possible. */

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
        throw error;
      }

      // meter operation usage
      metering.reportOperationUsage({req});
    }));
}

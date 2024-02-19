/*!
 * Copyright (c) 2018-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as slcs from './slcs.js';
import {
  issueCredentialBody,
  publishSlcBody,
  updateCredentialStatusBody
} from '../schemas/bedrock-vc-issuer.js';
import {metering, middleware} from '@bedrock/service-core';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import cors from 'cors';
import {issue} from './issuer.js';
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
    slc: `${baseUrl}${cfg.routes.slc}`
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
        const verifiableCredential = await issue({credential, config, options});
        res.status(201).json({verifiableCredential});
      } catch(error) {
        logger.error(error.message, {error});
        throw error;
      }

      // meter operation usage
      metering.reportOperationUsage({req});
    }));

  // update credential status
  app.options(routes.credentialsStatus, cors());
  app.post(
    routes.credentialsStatus,
    cors(),
    validate({bodySchema: updateCredentialStatusBody}),
    getConfigMiddleware,
    middleware.authorizeServiceObjectRequest(),
    asyncHandler(async (req, res) => {
      try {
        const {config} = req.serviceObject;
        const {credentialId, credentialStatus} = req.body;

        // FIXME: support client requesting `status=false` as well
        await slcs.setStatus({
          id: credentialId, config, credentialStatus, status: true
        });

        res.status(200).end();
      } catch(error) {
        logger.error(error.message, {error});
        throw error;
      }

      // meter operation usage
      metering.reportOperationUsage({req});
    }));

  // publish the latest SLC from EDV storage
  app.options(routes.publishSlc, cors());
  app.post(
    routes.publishSlc,
    cors(),
    validate({bodySchema: publishSlcBody}),
    getConfigMiddleware,
    middleware.authorizeServiceObjectRequest(),
    asyncHandler(async (req, res) => {
      const {config} = req.serviceObject;
      const {slcId} = req.params;
      const id = `${config.id}${cfg.routes.slcs}/${encodeURIComponent(slcId)}`;

      await slcs.publish({id, config});
      res.sendStatus(204);

      // meter operation usage
      metering.reportOperationUsage({req});
    }));

  // get latest published SLC, no-authz required
  app.get(
    routes.slc,
    cors(),
    getConfigMiddleware,
    asyncHandler(async (req, res) => {
      const {config} = req.serviceObject;
      const {slcId} = req.params;
      const id = `${config.id}${cfg.routes.slcs}/${encodeURIComponent(slcId)}`;
      while(true) {
        console.log('in get while loop');
        try {
          const record = await slcs.get({id});
          // refresh SLC if it has expired; get `now` as a minute into the
          // future to ensure the returned VC is still valid once returned to
          // the client
          const now = new Date();
          now.setTime(now.getTime() + 1000 * 60);
          // FIXME: support v2 VCs w/`validUntil`
          const validUntil = new Date(record.credential.expirationDate);
          if(now <= validUntil) {
            res.json(record.credential);
            return;
          }
          console.log('**********AUTO REFRESHING SLCS************');
          const doc = await slcs.refresh({id, config});
          res.json(doc.content);
          return;
        } catch(e) {
          if(e.name !== 'NotFoundError') {
            // unrecoverable error
            throw e;
          }
          try {
            // SLC not found, perhaps not published; try auto-publish
            console.log('***********AUTO PUBLISHING***********');
            await slcs.publish({id, config});
          } catch(publishError) {
            // log publication error
            logger.error(publishError.message, {error: publishError});
            // if publication fails, throw original `NotFoundError`
            throw e;
          }
        }
      }
    }));
}

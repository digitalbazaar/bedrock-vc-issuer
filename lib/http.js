/*!
 * Copyright (c) 2018-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as slcs from './slcs.js';
import {
  getMatchingStatusListConfig, issue, publishSlc, setStatus
} from './issuer.js';
import {
  issueCredentialBody,
  publishSlcBody,
  updateCredentialStatusBody
} from '../schemas/bedrock-vc-issuer.js';
import {metering, middleware} from '@bedrock/service-core';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import cors from 'cors';
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

        // options are not supported, everything must be preconfigured for
        // this issuer instance
        if(options) {
          throw new BedrockError(
            'Options not supported.',
            'NotSupportedError', {httpStatusCode: 400, public: true});
        }

        const verifiableCredential = await issue({credential, config});
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

        // check `credentialStatus` against status list options from `config`
        const match = getMatchingStatusListConfig({config, credentialStatus});

        // FIXME: support client requesting `status=false` as well
        await setStatus({
          id: credentialId, config, statusListConfig: match, status: true
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

      await publishSlc({id, config});
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
      const record = await slcs.get({id});
      res.json(record.credential);
    }));
}

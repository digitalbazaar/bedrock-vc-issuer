/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as slcs from './slcs.js';
import {asyncHandler} from 'bedrock-express';
import bedrock from 'bedrock';
import bodyParser from 'body-parser';
import cors from 'cors';
import {
  issueCredentialBody,
  updateCredentialStatusBody,
  publishSlcBody
} from '../schemas/bedrock-vc-issuer.js';
import {createValidateMiddleware as validate} from 'bedrock-validation';
import {issue, publishSlc, setStatus} from './issuer.js';
import {logger} from './logger.js';
import {metering, middleware} from 'bedrock-service-core';
const {util: {BedrockError}} = bedrock;

// FIXME: remove and apply at top-level application
bedrock.events.on('bedrock-express.configure.bodyParser', app => {
  app.use(bodyParser.json({limit: '10MB', type: ['json', '+json']}));
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
    // FIXME: add middleware to switch between oauth2 / zcap based on headers
    middleware.authorizeConfigZcapInvocation(),
    asyncHandler(async (req, res) => {
      try {
        const {config} = req.serviceObject;
        const {credential, options} = req.body;

        // handle options
        if(options) {
          // FIXME: support user-specified suite names?
          throw new BedrockError(
            'Options not supported.',
            'NotSupportedError', {httpStatusCode: 400, public: true});
        }

        const verifiableCredential = await issue(
          {credential, config/*, suiteName*/});
        res.status(201).json(verifiableCredential);
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
    // FIXME: add middleware to switch between oauth2 / zcap based on headers
    middleware.authorizeConfigZcapInvocation(),
    asyncHandler(async (req, res) => {
      try {
        const {config} = req.serviceObject;
        const {credentialId, credentialStatus} = req.body;

        // check `credentialStatus` against status types for `config`
        let match = false;
        const {statusListOptions = []} = config;
        for(const {statusType} of statusListOptions) {
          // FIXME: better generalize this
          if(statusType === 'revoked') {
            if(credentialStatus.type === 'RevocationList2020Status') {
              match = true;
              break;
            }
          }
        }

        if(!match) {
          throw new BedrockError(
            `Credential status type "${credentialStatus.type}" is not ` +
            'supported by this issuer instance.', 'NotSupportedError', {
              httpStatusCode: 400,
              public: true
            });
        }

        // FIXME: generalize use of `statusType`
        // FIXME: support client requesting `status=false` as well
        await setStatus({
          id: credentialId, config, statusType: 'revoked', status: true
        });

        res.status(200).end();
      } catch(error) {
        logger.error(error.message, {error});
        throw error;
      }

      // meter operation usage
      metering.reportOperationUsage({req});
    }));

  // public the latest SLC from EDV storage
  app.options(routes.publishSlc, cors());
  app.post(
    routes.publishSlc,
    cors(),
    validate({bodySchema: publishSlcBody}),
    getConfigMiddleware,
    // FIXME: add middleware to switch between oauth2 / zcap based on headers
    middleware.authorizeConfigZcapInvocation(),
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
    asyncHandler(async (req, res) => {
      const {config} = req.serviceObject;
      const {slcId} = req.params;
      const id = `${config.id}${cfg.routes.slcs}/${encodeURIComponent(slcId)}`;
      const record = await slcs.get({id});
      res.json(record.credential);
    }));
}

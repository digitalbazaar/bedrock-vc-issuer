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
import {serializeError} from 'serialize-error';
import {createValidateMiddleware as validate} from '@bedrock/validation';

const {util: {BedrockError}} = bedrock;

const ALLOWED_ERROR_KEYS = [
  'message', 'name', 'type', 'data', 'errors', 'error', 'details', 'cause',
  'status'
];

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
        // wrap if not already a BedrockError
        if(!(error instanceof BedrockError)) {
          _throwWrappedError({cause: error});
        }
        throw error;
      }

      // meter operation usage
      metering.reportOperationUsage({req});
    }));
}

// known error cause names to map to 'DataError'
const _dataErrors = new Set([
  'DataError',
  'jsonld.InvalidUrl',
  'jsonld.ValidationError'
]);
// TODO: handle other possible errors
// in particular @digitalbazaar/vc throws many simple 'TypeError' and
// 'Error' errors. Difficult to distinguish them from other errors.

function _throwWrappedError({cause}) {
  const {name/*, message*/} = cause;

  // TODO: should this be verbose with the top level error?  it's also in the
  // 'error' field.
  //const error = new BedrockError(message ?? 'Invalid credential.', {
  const error = new BedrockError('Invalid credential.', {
    name: _dataErrors.has(name) ? 'DataError' : 'OperationError',
    details: {
      // using sanitized 'error' field instead of 'cause' due to bedrock
      // currently filtering out non-BedrockError causes.
      error: _stripStackTrace(cause),
      httpStatusCode: cause.httpStatusCode ?? 400,
      public: true
    }
  });

  throw error;
}

function _stripStackTrace(error) {
  // serialize error and allow-list specific properties
  const serialized = serializeError(error);
  const _error = {};
  for(const key of ALLOWED_ERROR_KEYS) {
    if(serialized[key] !== undefined) {
      _error[key] = serialized[key];
    }
  }
  // strip other potential stack data
  if(_error.errors) {
    _error.errors = _error.errors.map(_stripStackTrace);
  }
  if(Array.isArray(_error.details?.errors)) {
    _error.details.errors = _error.details.errors.map(_stripStackTrace);
  }
  if(_error.cause) {
    _error.cause = _stripStackTrace(_error.cause);
  }
  if(_error.details?.cause) {
    _error.details.cause = _stripStackTrace(_error.details.cause);
  }
  return _error;
}

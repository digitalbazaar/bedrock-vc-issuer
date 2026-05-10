/*!
 * Copyright (c) 2020-2026 Digital Bazaar, Inc.
 */
import {config} from '@bedrock/core';
import '@bedrock/app-identity';
import '@bedrock/express';

const cfg = config['vc-issuer'] = {};

cfg.caches = {};

// document loader configuration for the issuer; all issuer instances
// will securely load DID documents using `bedrock-did-io` and any contexts
// that have been specifically added to them; these config options below
// also allow any issuer instance to optionally load `http` and `https`
// documents directly from the Web
cfg.documentLoader = {
  // `true` enables all issuers to fetch `http` documents from the Web
  http: false,
  // `true` enables all issuers to fetch `https` documents from the Web
  https: false
};

cfg.routes = {
  credentials: '/credentials',
  credentialsIssue: '/credentials/issue'
};

// enable larger payloads for certain routes
const createBodyParserOptions = ({limit}) => ({
  json: {
    strict: false,
    limit,
    type: ['json', '+json']
  }
});
const bodyParserRoutes = config.express.bodyParser.routes;
// max VC size is 10 MiB, allow for some overhead
bodyParserRoutes['/issuers/:instanceId/credentials/issue'] =
  createBodyParserOptions({limit: '11MB'});

// create dev application identity for vc-issuer (must be overridden in
// deployments) ...and `ensureConfigOverride` has already been set via
// `bedrock-app-identity` so it doesn't have to be set here
config['app-identity'].seeds.services['vc-issuer'] = {
  id: 'did:key:z6Mkvy68ASYcc1S5ZZdzkdBEwaiA8MKrHfDg74TEK32iV94M',
  seedMultibase: 'z1AeZSVFx4iDQkQPfLL9wpAE5Uzdd8zsdf5SjXtofYYXG58',
  serviceType: 'vc-issuer'
};

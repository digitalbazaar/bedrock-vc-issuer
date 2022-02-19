/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import bedrock from 'bedrock';

const {config} = bedrock;

const cfg = config['vc-issuer'] = {};

// document loader configuration for the issuer; all issuer instances
// will securely load DID documents using `bedrock-did-io` and any contexts
// that have been specifically added to them; these config options below
// also allow any issuer instance to optionally load `http` and `https`
// documents directly from the Web
cfg.documentLoader = {
  // `true` enables all issuers to fetch `http` documents from the Web
  http: false,
  // `true` enables all issuers to fetch `https` documents from the Web
  https: true
};

cfg.routes = {
  credentialsIssue: '/credentials/issue',
  credentialsStatus: '/credentials/status',
  // `slcs` route must be a prefix for `publishSlc` and `slc`
  publishSlc: '/slcs/:slcId/publish',
  slc: '/slcs/:slcId',
  slcs: '/slcs'
};

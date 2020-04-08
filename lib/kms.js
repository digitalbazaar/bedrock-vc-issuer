/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
const brHttpsAgent = require('bedrock-https-agent');
const {
  AsymmetricKey,
  KeyAgreementKey,
  KmsClient,
} = require('webkms-client');

// load config defaults
require('./config');

exports.createAsymmetricKey = ({invocationSigner, zcap}) => {
  const {httpsAgent} = brHttpsAgent;
  return new AsymmetricKey({
    capability: zcap,
    invocationSigner,
    kmsClient: new KmsClient({httpsAgent}),
  });
};

exports.createKak = ({invocationSigner, zcap}) => {
  const {httpsAgent} = brHttpsAgent;
  return new KeyAgreementKey({
    id: zcap.invocationTarget.id,
    type: zcap.invocationTarget.type,
    capability: zcap,
    invocationSigner,
    kmsClient: new KmsClient({httpsAgent}),
  });
};

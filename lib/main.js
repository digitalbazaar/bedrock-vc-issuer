/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as issuer from './issuer.js';
import {addRoutes} from './http.js';
import bedrock from 'bedrock';
import {
  addRoutes as addContextStoreRoutes
} from 'bedrock-service-context-store';
import {createService, schemas} from 'bedrock-service-core';
import {initializeServiceAgent} from 'bedrock-service-agent';
import {
  issueOptions, statusListOptions
} from '../schemas/bedrock-vc-issuer.js';

// load config defaults
import './config.js';

export {issuer};

const serviceType = 'vc-issuer';

bedrock.events.on('bedrock.init', async () => {
  // add customizations to config validators...
  const createConfigBody = bedrock.util.clone(schemas.createConfigBody);
  const updateConfigBody = bedrock.util.clone(schemas.updateConfigBody);
  const schemasToUpdate = [createConfigBody, updateConfigBody];
  for(const schema of schemasToUpdate) {
    // add ability to configure `statusListOptions`; must be present to use
    // credential status in VCs
    schema.properties.statusListOptions = statusListOptions;
    // require issue options
    schema.required.push('issueOptions');
    schema.properties.issueOptions = issueOptions;
  }

  // create `vc-issuer` service
  const service = await createService({
    serviceType,
    routePrefix: '/issuers',
    storageCost: {
      config: 1,
      revocation: 1
    },
    // require these zcaps (by reference ID)
    validation: {
      createConfigBody,
      updateConfigBody,
      validateConfigFn,
      zcapReferenceIds: [{
        referenceId: 'edv',
        required: true
      }, {
        referenceId: 'hmac',
        required: true
      }, {
        referenceId: 'keyAgreementKey',
        required: true
      }, {
        referenceId: 'assertionMethod:ed25519',
        // FIXME: when other assertion methods are supported, make this `false`
        required: true
      }]
    }
  });

  bedrock.events.on('bedrock-express.configure.routes', async app => {
    await addContextStoreRoutes({app, service});
    await addRoutes({app, service});
  });

  // initialize vc-issuer service agent early (after database is ready) if
  // KMS system is externalized; otherwise we must wait until KMS system
  // is ready
  const externalKms = !bedrock.config['service-agent'].kms.baseUrl.startsWith(
    bedrock.config.server.baseUri);
  const event = externalKms ? 'bedrock-mongodb.ready' : 'bedrock.ready';
  bedrock.events.on(event, async () => {
    await initializeServiceAgent({serviceType});
  });
});

async function validateConfigFn({/*config, op*/} = {}) {
  // FIXME: ensure config `issueOptions` and `statusListOptions` have
  // matching zcaps, etc.

  return {valid: true};
}

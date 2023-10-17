/*!
 * Copyright (c) 2021-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as issuer from './issuer.js';
import {createService, schemas} from '@bedrock/service-core';
import {
  issueOptions, statusListOptions
} from '../schemas/bedrock-vc-issuer.js';
import {
  addRoutes as addContextStoreRoutes
} from '@bedrock/service-context-store';
import {addRoutes} from './http.js';
import {getSuiteParams} from './suites.js';
import {initializeServiceAgent} from '@bedrock/service-agent';
import {klona} from 'klona';

// load config defaults
import './config.js';

export {issuer};

const serviceType = 'vc-issuer';

bedrock.events.on('bedrock.init', async () => {
  // add customizations to config validators...
  const createConfigBody = klona(schemas.createConfigBody);
  const updateConfigBody = klona(schemas.updateConfigBody);
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
    validation: {
      createConfigBody,
      updateConfigBody,
      validateConfigFn,
      // require these zcaps (by reference ID)
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
        referenceId: 'assertionMethod',
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

async function validateConfigFn({config} = {}) {
  try {
    // only 1 status list config allowed at this time
    const {issueOptions, statusListOptions = []} = config;
    if(statusListOptions.length > 1) {
      throw new Error(
        'Only one status list configuration per issuer instance is ' +
        'presently supported.');
    }

    // ensure suite parameters can be retrieved for the configured
    // `issueOptions` and `statusListOptions`...
    getSuiteParams({config, suiteName: issueOptions.suiteName});
    for(const {type, statusPurpose, suiteName} of statusListOptions) {
      // `statusPurpose` MUST be `revocation` if using type `RevocationList2020`
      if(type === 'RevocationList2020' && statusPurpose !== 'revocation') {
        throw new Error(
          '"RevocationList2020" only supports a status purpose of ' +
          '"revocation".');
      }

      getSuiteParams({config, suiteName});
    }
  } catch(error) {
    return {valid: false, error};
  }
  return {valid: true};
}

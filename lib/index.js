/*!
 * Copyright (c) 2021-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as issuer from './issuer.js';
import {createService, schemas} from '@bedrock/service-core';
import {
  DEFAULT_BLOCK_COUNT, DEFAULT_BLOCK_SIZE, DEFAULT_TERSE_LIST_COUNT,
  MAX_LIST_SIZE, MAX_STATUS_LIST_OPTIONS, serviceType
} from './constants.js';
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
import {v4 as uuid} from 'uuid';

// load config defaults
import './config.js';

export {issuer};

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
    // require `zcaps`
    schema.required.push('zcaps');
    schema.properties.zcaps = klona(schemas.zcaps);
    // required zcap reference IDs
    // note: `assertionMethod` not required for backwards compatibility
    // purposes (as it has used other reference IDs in the past)
    schema.properties.zcaps.required = ['edv', 'hmac', 'keyAgreementKey'];
    // max of 4 required zcaps + 1 per status list option
    schema.properties.zcaps.maxProperties = 4 + MAX_STATUS_LIST_OPTIONS;
    schema.properties.zcaps.additionalProperties = schemas.delegatedZcap;
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
      validateConfigFn
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

async function validateConfigFn({config, op, existingConfig} = {}) {
  try {
    // only 1 status list config allowed at this time
    const {issueOptions, statusListOptions = []} = config;
    if(statusListOptions.length > 1) {
      throw new Error(
        'Only one status list configuration per issuer instance is ' +
        'presently supported.');
    }

    // prevent changes in status list configs to avoid any potential index
    // allocation corruption
    // note: this could perhaps be relaxed in the future to some extent but
    // analysis is required
    if(op === 'update' && existingConfig.statusListOptions !== undefined &&
      config.statusListOptions !== undefined) {
      const {statusListOptions: existingStatusListOptions} = existingConfig;
      if(JSON.stringify(statusListOptions) !==
        JSON.stringify(existingStatusListOptions)) {
        throw new Error('Status list options cannot be changed.');
      }
    }

    // ensure suite parameters can be retrieved for the configured
    // `issueOptions` and `statusListOptions`...
    getSuiteParams({config, suiteName: issueOptions.suiteName});
    for(const statusConfig of statusListOptions) {
      const {type, suiteName} = statusConfig;

      // each status list config must have a globally unambiguous
      // `indexAllocator` ID to be associated with each status list service
      // to help avoid accidental concurrent use by multiple issuer instances
      // which can resulting in corruption / reuse of indexes for different
      // VCs
      if(op === 'create' && statusConfig.indexAllocator === undefined) {
        statusConfig.indexAllocator = `urn:uuid:${uuid()}`;
      }
      if(statusConfig.indexAllocator === undefined) {
        throw new Error(
          'Each status list configuration requires an "indexAllocator".');
      }

      // set default options
      const options = {
        blockCount: DEFAULT_BLOCK_COUNT,
        blockSize: DEFAULT_BLOCK_SIZE,
        ...statusConfig.options
      };
      // ensure list size is a multiple of 8 and less than the max list size
      const listSize = options.blockCount * options.blockSize;
      if(listSize % 8 !== 0) {
        throw new Error(
          `Total status list size (${listSize}) must be a multiple of 8.`);
      }
      if(listSize > MAX_LIST_SIZE) {
        throw new Error(
          `Total status list size (${listSize}) must be less than ` +
          `${MAX_LIST_SIZE}.`);
      }
      // `listCount` checks...
      if(options.listCount !== undefined) {
        // FIXME: re-enable this check
        /*if(type !== 'TerseBitstringStatusList') {
          throw new Error(
            '"listCount" can only be used with "TerseBitstringStatusList".');
        }*/
      }
      if(type === 'TerseBitstringStatusList') {
        // must be a list count for `TerseBitstringStatusList`
        if(options.listCount === undefined) {
          options.listCount = DEFAULT_TERSE_LIST_COUNT;
        }
      }
      statusConfig.options = options;

      // FIXME: hard require `baseUrl` once status service is separated
      // ensure base URL is set for new status list creation
      if(statusConfig.baseUrl === undefined) {
        // const suffix = options.listCount === undefined ?
        //   bedrock.config['vc-issuer'].routes.slcs :
        //   bedrock.config['vc-issuer'].routes.terseSlcs;
        const {
          createCredentialStatusList: referenceId
        } = statusConfig.zcapReferenceIds;
        const zcap = config.zcaps[referenceId];
        statusConfig.baseUrl = zcap.invocationTarget;
      }

      getSuiteParams({config, suiteName});
    }
  } catch(error) {
    return {valid: false, error};
  }
  return {valid: true};
}

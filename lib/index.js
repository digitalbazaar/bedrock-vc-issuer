/*!
 * Copyright (c) 2021-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as issuer from './issuer.js';
import {createService, schemas} from '@bedrock/service-core';
import {
  DEFAULT_BLOCK_COUNT, DEFAULT_BLOCK_SIZE, DEFAULT_TERSE_LIST_COUNT,
  MAX_BLOCK_COUNT, MAX_BLOCK_SIZE,
  MAX_CRYPTOSUITE_OPTIONS, MAX_LIST_SIZE, MAX_STATUS_LIST_OPTIONS, serviceType
} from './constants.js';
import {
  issueOptions, statusListOptions
} from '../schemas/bedrock-vc-issuer.js';
import {
  addRoutes as addContextStoreRoutes
} from '@bedrock/service-context-store';
import {addRoutes} from './http.js';
import {getEnvelopeParams} from './envelopes.js';
import {getSuiteParams} from './suites.js';
import {initializeServiceAgent} from '@bedrock/service-agent';
import {randomUUID as uuid} from 'node:crypto';

// load config defaults
import './config.js';

export {issuer};

bedrock.events.on('bedrock.init', async () => {
  // add customizations to config validators...
  const createConfigBody = structuredClone(schemas.createConfigBody);
  const updateConfigBody = structuredClone(schemas.updateConfigBody);
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
    schema.properties.zcaps = structuredClone(schemas.zcaps);
    // required zcap reference IDs
    // note: `assertionMethod` not required for backwards compatibility
    // purposes (as it has used other reference IDs in the past)
    schema.properties.zcaps.required = ['edv', 'hmac', 'keyAgreementKey'];
    // max of 3 required zcaps + refresh zcap +
    // max cryptosuites opts + max status lists opts
    schema.properties.zcaps.maxProperties =
      3 + 1 + MAX_CRYPTOSUITE_OPTIONS + MAX_STATUS_LIST_OPTIONS;
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
    },
    async refreshHandler({record, signal}) {
      // refresh zcaps and update record w/results
      const result = await refreshZcaps({
        serviceType, config: record.config, signal
      });
      const config = result.config ?? record.config;
      await service.configStorage.update({
        config: {...config, sequence: config.sequence + 1},
        refresh: result.refresh
      });
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

    if(issueOptions.suiteName) {
      // ensure suite parameters can be retrieved for configured `issueOptions`
      getSuiteParams({config, suiteName: issueOptions.suiteName});
    } else {
      if(issueOptions.cryptosuites) {
        // ensure every suite's params can be retrieved
        for(const cryptosuite of issueOptions.cryptosuites) {
          getSuiteParams({config, cryptosuite});
        }
      }
      // ensure envelope's params can be retrieved
      if(issueOptions.envelope) {
        getEnvelopeParams({config, envelope: issueOptions.envelope});
      }
    }

    // validate `statusListOptions`...
    for(const statusConfig of statusListOptions) {
      const {type} = statusConfig;

      // each status list config must have a globally unambiguous
      // `indexAllocator` ID to be associated with each status list service
      // to help avoid accidental concurrent use by multiple issuer instances
      // which can resulting in corruption / reuse of indexes for different VCs
      if(op === 'create' && statusConfig.indexAllocator === undefined) {
        statusConfig.indexAllocator = `urn:uuid:${uuid()}`;
      }
      if(statusConfig.indexAllocator === undefined) {
        throw new Error(
          'Each status list configuration requires an "indexAllocator".');
      }

      // set default options
      let options;
      if(type === 'TerseBitstringStatusList') {
        options = {
          // must use max block count and size for terse defaults
          blockCount: MAX_BLOCK_COUNT,
          blockSize: MAX_BLOCK_SIZE,
          // must be a list count for `TerseBitstringStatusList`
          listCount: DEFAULT_TERSE_LIST_COUNT,
          ...statusConfig.options
        };
      } else {
        // other list types
        options = {
          blockCount: DEFAULT_BLOCK_COUNT,
          blockSize: DEFAULT_BLOCK_SIZE,
          ...statusConfig.options
        };
      }
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
      if(options.listCount !== undefined) {
        if(type !== 'TerseBitstringStatusList') {
          throw new Error(
            '"listCount" can only be used with "TerseBitstringStatusList".');
        }
      }
      statusConfig.options = options;

      // default `baseUrl` to the invocation target of the zcap for
      // creating status lists
      if(statusConfig.baseUrl === undefined) {
        const {
          createCredentialStatusList: referenceId
        } = statusConfig.zcapReferenceIds;
        const zcap = config.zcaps[referenceId];
        statusConfig.baseUrl = zcap.invocationTarget;
      }
    }
  } catch(error) {
    return {valid: false, error};
  }
  return {valid: true};
}

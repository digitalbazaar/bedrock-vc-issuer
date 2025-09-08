/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import {createZcapClient} from './helpers.js';
import {serviceAgents} from '@bedrock/service-agent';
import {serviceType} from './constants.js';

export class ListSource {
  constructor({config, statusListConfig} = {}) {
    assert.object(config, 'config');
    assert.object(statusListConfig, 'statusListConfig');
    this.config = config;
    this.statusListConfig = statusListConfig;
  }

  async createStatusList({
    id, statusPurpose, length, handleDuplicate = true
  } = {}) {
    let statusListId;
    try {
      // get zcap for `statusListConfig` for creating status lists
      const {config, statusListConfig} = this;
      const {serviceAgent} = await serviceAgents.get({serviceType});
      const {
        capabilityAgent, zcaps
      } = await serviceAgents.getEphemeralAgent({config, serviceAgent});
      const {
        createCredentialStatusList: referenceId
      } = statusListConfig.zcapReferenceIds;
      const capability = zcaps[referenceId];

      // if `statusListConfig.type` is `TerseBitstringStatusList`, then the
      // created list will be a `BitstringStatusList`, it will just use a
      // statusPurpose-namespaced URL and an integer for the namespaced list ID
      const statusListType =
        statusListConfig.type === 'TerseBitstringStatusList' ?
          'BitstringStatusList' : statusListConfig.type;

      // create status list...
      const zcapClient = createZcapClient({capabilityAgent});
      // status list URL/ID must use the same suffix as the VC ID to enable
      // deployment redirection possibilities whilst being able to derive the
      // status list ID on the status service from the VC ID
      const suffix = id.slice(
        id.lastIndexOf('/status-lists/') + '/status-lists'.length);
      const url = `${capability.invocationTarget}${suffix}`;
      statusListId = url;
      const statusListOptions = {
        credentialId: id,
        type: statusListType,
        indexAllocator: statusListConfig.indexAllocator,
        length,
        statusPurpose
      };
      const response = await zcapClient.write({
        url, capability, json: statusListOptions
      });
      statusListId = response?.headers?.get('location');
      return {statusListId};
    } catch(e) {
      // if duplicates are to be auto-handled, then if the new status list
      // couldn't be added because of an invalid state or conflict error,
      // return the computed status list ID
      if(handleDuplicate && (
        e.data?.name === 'InvalidStateError' ||
        e.data?.name === 'ConflictError' ||
        e.data?.details?.httpStatusCode === 409)) {
        return {statusListId};
      }
      throw e;
    }
  }
}

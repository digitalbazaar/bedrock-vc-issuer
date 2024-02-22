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

  async createStatusList({id, statusPurpose, length}) {
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

    // create status list...
    const zcapClient = createZcapClient({capabilityAgent});
    // status list URL/ID must use the same suffix as the VC ID to enable
    // deployment redirection possibilities whilst being able to derive the
    // status list ID on the status service from the VC ID
    const suffix = id.slice(
      id.lastIndexOf('/status-lists/') + '/status-lists'.length);
    const url = `${capability.invocationTarget}${suffix}`;
    const statusListOptions = {
      credentialId: id,
      // FIXME: support other types
      type: 'StatusList2021',
      indexAllocator: statusListConfig.indexAllocator,
      length,
      statusPurpose
    };
    const response = await zcapClient.write({
      url, capability, json: statusListOptions
    });
    const statusListId = response?.headers?.get('location');
    return {statusListId};
  }
}

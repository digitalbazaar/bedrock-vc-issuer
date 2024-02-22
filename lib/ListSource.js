/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  createList as createList2021,
  createCredential as createSlc
} from '@digitalbazaar/vc-status-list';
import assert from 'assert-plus';
import {createZcapClient} from './helpers.js';
import {issue} from './helpers.js';
import {serviceAgents} from '@bedrock/service-agent';
import {serviceType} from './constants.js';

export class ListSource {
  constructor({
    config, statusListConfig, documentLoader, edvClient,
    issuer, suite
  } = {}) {
    assert.object(config, 'config');
    assert.object(statusListConfig, 'statusListConfig');
    assert.func(documentLoader, 'documentLoader');
    assert.object(edvClient, 'edvClient');
    assert.string(issuer, 'issuer');
    assert.object(suite, 'suite');
    if(!issuer) {
      throw new TypeError('"issuer" must be a non-empty string.');
    }
    this.config = config;
    this.statusListConfig = statusListConfig;
    this.documentLoader = documentLoader;
    this.edvClient = edvClient;
    this.issuer = issuer;
    this.suite = suite;
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
    console.log('***CREATED STATUS LIST', statusListId);

    // FIXME: creating a list on the status service should also involve
    // including an index allocator ID for that list, to avoid accidental
    // misuse of the list (e.g., sharing with multiple issuer instances that
    // might allocate indexes differently) by authorized parties; the same
    // ID could be used for multiple SLs and it doesn't have to identify a
    // particular issuer instance, but it should identify, to an issuer
    // instance, which index allocation state is associated with the SL; this
    // ID should be provided when the SL is created and whenever a credential
    // is associated with an index/an index value is updated w/o a credential
    // FIXME: call out to status service
    //await this._ensureStatusListCredentialExists({id, statusPurpose, length});
  }

  // FIXME: move to status service
  async _createStatusListCredential({id, type, statusPurpose, length}) {
    if(type === 'StatusList2021') {
      const list = await createList2021({length});
      return createSlc({id, list, statusPurpose});
    }
    // FIXME: implement `BitstringStatusList`
    throw new Error('Not implemented.');
  }

  // FIXME: status service should handle this instead
  async _ensureStatusListCredentialExists({id, statusPurpose, length}) {
    const {statusListConfig, documentLoader, edvClient} = this;

    // try to create SLC credential and EDV doc...
    const {suite, issuer} = this;
    // FIXME: create list without having to issue VC; issue VC on demand
    // instead
    const credential = await this._createStatusListCredential({
      id, type: 'StatusList2021', statusPurpose, length
    });
    credential.issuer = issuer;
    credential.name = 'Status List Credential';
    credential.description =
      `This credential expresses status information for some ` +
      'other credentials in an encoded and compressed list.';
    // express date without milliseconds
    const date = new Date();
    // TODO: use `validFrom` and `validUntil` for v2 VCs
    credential.issuanceDate = `${date.toISOString().slice(0, -5)}Z`;
    // FIXME: get validity period via status service instance config
    date.setDate(date.getDate() + 1);
    credential.expirationDate = `${date.toISOString().slice(0, -5)}Z`;
    const verifiableCredential = await issue(
      {credential, documentLoader, suite});
    const doc = {
      id: await edvClient.generateId(),
      content: verifiableCredential,
      // include `meta.type` as a non-user input type to validate against
      meta: {type: 'VerifiableCredential', statusListConfig}
    };
    try {
      await edvClient.update({doc});
    } catch(e) {
      if(e.name !== 'DuplicateError') {
        throw e;
      }
      // duplicate, ignore as another process created the SLC
    }
  }
}

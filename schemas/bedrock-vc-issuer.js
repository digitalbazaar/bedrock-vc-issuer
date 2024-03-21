/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  DEFAULT_BLOCK_COUNT, DEFAULT_BLOCK_SIZE, MAX_LIST_COUNT,
  MAX_STATUS_LIST_OPTIONS
} from '../lib/constants.js';

const context = {
  title: '@context',
  type: 'array',
  minItems: 1,
  items: {
    type: ['string', 'object']
  }
};

export const issueOptions = {
  title: 'Issue Options',
  type: 'object',
  required: ['suiteName'],
  additionalProperties: false,
  properties: {
    suiteName: {
      type: 'string',
      // supported default suites in this version
      enum: [
        'ecdsa-rdfc-2019', 'eddsa-rdfc-2022', 'Ed25519Signature2020',
        'Ed25519Signature2018', 'ecdsa-sd-2023', 'ecdsa-xi-2023'
      ]
    }
  }
};

export const statusListConfig = {
  title: 'Status List Configuration',
  type: 'object',
  required: ['type', 'statusPurpose', 'zcapReferenceIds'],
  additionalProperties: false,
  properties: {
    type: {
      type: 'string',
      // supported types in this version
      enum: [
        'BitstringStatusList',
        // FIXME: consider removing `StatusList2021` support
        'StatusList2021',
        'TerseBitstringStatusList'
      ]
    },
    // base URL to use for new lists, defaults to `invocationTarget` from
    // zcap referred to by `createCredentialStatusList` reference ID
    baseUrl: {
      type: 'string'
    },
    // an ID value required to track index allocation and used with external
    // status list service; can be auto-generated, so not required
    indexAllocator: {
      // an ID (URL) referring to an index allocator
      type: 'string'
    },
    // note: scoped to `type`
    statusPurpose: {
      // FIXME: also support array with multiple status purposes; triggers
      // creation of multiple lists
      type: 'string',
      // supported status types in this version
      enum: ['revocation', 'suspension']
    },
    // note: scoped to `type`; will be auto-populated with defaults so not
    // required
    options: {
      type: 'object',
      additionalProperties: false,
      properties: {
        blockCount: {
          type: 'integer',
          minimum: 1,
          maximum: DEFAULT_BLOCK_COUNT
        },
        blockSize: {
          type: 'integer',
          minimum: 1,
          maximum: DEFAULT_BLOCK_SIZE
        },
        // note: some list types will require a `listCount`, each having their
        // own different list count limits and defaults applied elsewhere; the
        // `MAX_LIST_COUNT` here is the maximum this software can keep track of
        listCount: {
          type: 'integer',
          minimum: 1,
          maximum: MAX_LIST_COUNT
        }
      }
    },
    // zcap reference IDs reference zcaps in the root config
    zcapReferenceIds: {
      type: 'object',
      required: ['createCredentialStatusList'],
      additionalProperties: false,
      properties: {
        createCredentialStatusList: {
          type: 'string'
        }
      }
    }
  }
};

export const statusListOptions = {
  title: 'Status List Options',
  type: 'array',
  minItems: MAX_STATUS_LIST_OPTIONS,
  items: statusListConfig
};

export const issueCredentialBody = {
  title: 'Issue Credential',
  type: 'object',
  required: ['credential'],
  additionalProperties: false,
  properties: {
    options: {
      type: 'object',
      additionalProperties: false,
      properties: {
        credentialId: {
          type: 'string'
        },
        mandatoryPointers: {
          type: 'array',
          minItems: 0,
          items: {
            type: 'string'
          }
        },
        extraInformation: {
          type: 'string'
        }
      }
    },
    credential: {
      type: 'object',
      additionalProperties: true,
      required: ['@context'],
      properties: {
        '@context': context
      }
    }
  }
};

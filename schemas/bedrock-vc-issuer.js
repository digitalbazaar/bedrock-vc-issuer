/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {MAX_BLOCK_COUNT, MAX_BLOCK_SIZE} from '../lib/constants.js';

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
        'Ed25519Signature2018', 'ecdsa-sd-2023'
      ]
    }
  }
};

// FIXME: support specifying multiple statuses (triggering multiple lists)
// FIXME: support external status service w/zcap(s) and expression of the
//   target types (TerseBitstringStatusList, BitstringStatusList)
export const statusListConfig = {
  title: 'Status List Configuration',
  type: 'object',
  required: ['type', 'suiteName', 'statusPurpose'],
  additionalProperties: false,
  properties: {
    // FIXME: each status list config might need a unique ID for list manager
    // tracking purposes; notably, an `id` (or other mechanism) already needs
    // to be associated with each SL that is created on a status service to
    // help avoid accidental concurrent use by multiple issuer instances --
    // potentially resulting in corruption / reuse of indexes for different
    // VCs -- and this could be reused for that purpose
    type: {
      type: 'string',
      // supported types in this version
      enum: ['StatusList2021', 'RevocationList2020']
    },
    suiteName: {
      type: 'string',
      // supported suites in this version
      enum: [
        'ecdsa-rdfc-2019', 'eddsa-rdfc-2022', 'Ed25519Signature2020',
        'Ed25519Signature2018', 'ecdsa-sd-2023'
      ]
    },
    // note: scoped to `type`
    statusPurpose: {
      type: 'string',
      // supported status types in this version
      enum: ['revocation', 'suspension']
    },
    // note: scoped to `type`
    options: {
      type: 'object',
      additionalProperties: false,
      properties: {
        blockCount: {
          type: 'integer',
          minimum: 1,
          maximum: MAX_BLOCK_COUNT
        },
        blockSize: {
          type: 'integer',
          minimum: 1,
          maximum: MAX_BLOCK_SIZE
        }
      }
    }
  }
};

export const statusListOptions = {
  title: 'Status List Options',
  type: 'array',
  minItems: 1,
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
        mandatoryPointers: {
          type: 'array',
          minItems: 0,
          items: {
            type: 'string'
          }
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

export const updateCredentialStatusBody = {
  title: 'Update Credential Status',
  type: 'object',
  required: ['credentialId', 'credentialStatus'],
  additionalProperties: false,
  properties: {
    credentialId: {
      type: 'string'
    },
    credentialStatus: {
      type: 'object',
      required: ['type'],
      additionalProperties: false,
      properties: {
        type: {
          type: 'string'
        },
        statusPurpose: {
          type: 'string'
        }
      }
    }
  }
};

export const publishSlcBody = {
  title: 'Publish Status List Credential',
  type: 'object',
  additionalProperties: false,
  // body must be empty
  properties: {}
};

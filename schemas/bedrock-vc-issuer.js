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

const zcapReferenceIds = {
  title: 'Authorization Capability Reference IDs',
  type: 'object',
  required: ['assertionMethod'],
  additionalProperties: false,
  properties: {
    assertionMethod: {
      type: 'string'
    }
  }
};

const cryptosuite = {
  title: 'Cryptosuite Options',
  type: 'object',
  required: ['name', 'zcapReferenceIds'],
  additionalProperties: false,
  properties: {
    name: {
      type: 'string',
      // supported default suites in this version
      enum: [
        'ecdsa-rdfc-2019', 'eddsa-rdfc-2022', 'Ed25519Signature2020',
        'Ed25519Signature2018', 'ecdsa-sd-2023', 'ecdsa-xi-2023',
        'bbs-2023'
      ]
    },
    zcapReferenceIds
  }
};

const cryptosuites = {
  title: 'Cryptosuites',
  type: 'array',
  additionalItems: false,
  minItems: 1,
  items: cryptosuite
};

const envelope = {
  title: 'Envelope Options',
  type: 'object',
  required: ['format', 'zcapReferenceIds'],
  additionalProperties: false,
  properties: {
    format: {
      type: 'string',
      // supported default envelope formats in this version
      enum: [
        'VC-JWT'
      ]
    },
    // FIXME: `algorithm` / similar required
    zcapReferenceIds
  }
};

export const issueOptions = {
  title: 'Issue Options',
  type: 'object',
  oneOf: [{
    // preferred mechanism for specifying issuer and cryptosuites to sign with
    required: ['issuer', 'cryptosuites'],
    not: {
      required: ['suiteName']
    }
  }, {
    // preferred mechanism for specifying issuer and envelope to use
    required: ['issuer', 'envelope'],
    not: {
      required: ['suiteName']
    }
  }, {
    // legacy; for backwards compatibility only
    required: ['suiteName'],
    not: {
      required: ['issuer', 'cryptosuites', 'envelope']
    }
  }],
  additionalProperties: false,
  properties: {
    // modern
    issuer: {
      type: 'string'
    },
    // embedded proof security
    cryptosuites,
    // envelope security
    envelope,
    // legacy
    suiteName: {
      type: 'string',
      // supported default suites in this version
      enum: [
        'ecdsa-rdfc-2019', 'eddsa-rdfc-2022', 'Ed25519Signature2020',
        'Ed25519Signature2018', 'ecdsa-sd-2023', 'ecdsa-xi-2023',
        'bbs-2023'
      ]
    }
  }
};

// supported status purposes in this version
const statusPurposes = ['revocation', 'suspension'];

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
      oneOf: [{
        type: 'string',
        enum: statusPurposes
      }, {
        // array usage triggers creation of multiple lists
        type: 'array',
        minItems: 1,
        items: {
          type: 'string',
          enum: statusPurposes
        },
        uniqueItems: true
      }]
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

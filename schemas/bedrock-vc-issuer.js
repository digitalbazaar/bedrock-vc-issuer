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

const mandatoryPointers = {
  type: 'array',
  minItems: 0,
  items: {
    type: 'string'
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
        'ecdsa-rdfc-2019', 'eddsa-rdfc-2022', 'ecdsa-jcs-2019',
        'eddsa-jcs-2022', 'Ed25519Signature2020', 'Ed25519Signature2018',
        'ecdsa-sd-2023', 'ecdsa-xi-2023', 'bbs-2023'
      ]
    },
    options: {
      title: 'Cryptosuite options',
      type: 'object',
      additionalProperties: false,
      properties: {
        includeCreated: {
          type: 'boolean'
        },
        mandatoryPointers
      }
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
    options: {
      title: 'Envelope options',
      type: 'object',
      additionalProperties: false,
      properties: {
        alg: {
          type: 'string',
          enum: ['ES256', 'EdDSA', 'Ed25519']
        }
      }
    },
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
        'ecdsa-rdfc-2019', 'eddsa-rdfc-2022', 'ecdsa-jcs-2019',
        'eddsa-jcs-2022', 'Ed25519Signature2020', 'Ed25519Signature2018',
        'ecdsa-sd-2023', 'ecdsa-xi-2023', 'bbs-2023'
      ]
    }
  }
};

// supported status purposes in this version
const statusPurposes = ['activation', 'revocation', 'suspension'];

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

const vcdmType = {
  title: 'VCDM Type',
  oneOf: [{
    type: 'string'
  }, {
    type: 'array',
    items: {
      minItems: 1,
      items: {
        type: ['string']
      }
    }
  }]
};

const vcdmObject = {
  title: 'VCDM Object',
  type: 'object',
  additionalProperties: true,
  properties: {
    id: {
      type: 'string'
    },
    type: vcdmType
  }
};

const vcdmTypedObject = {
  ...vcdmObject,
  required: ['type']
};

const vcdmObjectOrReference = {
  title: 'VCDM Object or Reference',
  oneOf: [vcdmObject, {
    type: 'string'
  }]
};

const vcdmObjectSet = {
  title: 'VCDM Object Set',
  oneOf: [vcdmObject, {
    type: 'array',
    minItems: 1,
    items: vcdmObject
  }]
};

const vcdmObjectOrReferenceSet = {
  title: 'VCDM Object or Reference Set',
  oneOf: [vcdmObjectOrReference, {
    type: 'array',
    minItems: 1,
    items: vcdmObjectOrReference
  }]
};

const vcdmTypedObjectSet = {
  title: 'VCDM Typed Object Set',
  oneOf: [vcdmTypedObject, {
    type: 'array',
    minItems: 1,
    items: vcdmTypedObject
  }]
};

const languageObject = {
  type: 'object',
  required: ['@value'],
  additionalProperties: false,
  properties: {
    '@value': {
      type: 'string'
    },
    '@direction': {
      type: 'string'
    },
    '@language': {
      type: 'string'
    }
  }
};

const valueStringOrObject = {
  anyOf: [{type: 'string'}, languageObject]
};

const languageValue = {
  anyOf: [
    valueStringOrObject,
    {type: 'array', minItems: 1, items: valueStringOrObject}
  ]
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
        mandatoryPointers,
        extraInformation: {
          type: 'string'
        }
      }
    },
    credential: {
      type: 'object',
      additionalProperties: true,
      required: ['@context', 'type'],
      properties: {
        '@context': context,
        type: vcdmType,
        confidenceMethod: vcdmTypedObjectSet,
        credentialSchema: vcdmTypedObjectSet,
        credentialStatus: vcdmTypedObjectSet,
        credentialSubject: vcdmObjectOrReferenceSet,
        description: languageValue,
        evidence: vcdmTypedObjectSet,
        // `issuer` skipped, handled internally during issuance
        name: languageValue,
        proof: vcdmTypedObjectSet,
        refreshService: vcdmTypedObjectSet,
        relatedResource: vcdmObjectSet,
        renderMethod: vcdmTypedObjectSet,
        termsOfUse: vcdmTypedObjectSet,
        validFrom: {
          // FIXME: improve date validation
          type: 'string'
        },
        validUntil: {
          // FIXME: improve date validation
          type: 'string'
        },
        // VC 1.1 properties
        issuanceDate: {
          type: 'string'
        },
        expirationDate: {
          type: 'string'
        }
      }
    }
  }
};

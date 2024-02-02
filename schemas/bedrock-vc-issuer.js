/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
const context = {
  title: '@context',
  type: 'array',
  minItems: 1,
  items: {
    type: ['string', 'object']
  }
};

// a supported cryptosuite name
const suiteName = {
  type: 'string',
  // supported default suites in this version
  enum: [
    'ecdsa-rdfc-2019', 'eddsa-rdfc-2022', 'Ed25519Signature2020',
    'Ed25519Signature2018', 'ecdsa-sd-2023'
  ]
};

// allows an issuer to sign with multiple cryptosuites with custom defaults.
const suiteOption = {
  type: 'object',
  additionalProperties: false,
  required: ['cryptosuite'],
  properties: {
    cryptosuite: suiteName,
    options: {
      type: 'object',
      additionalProperties: true
    }
  }
};

export const issueOptions = {
  title: 'Issue Options',
  type: 'object',
  oneOf: [{required: ['suiteName']}, {required: ['cryptosuites']}],
  additionalProperties: false,
  properties: {
    suiteName,
    cryptosuites: {
      type: 'array',
      items: suiteOption,
      minItems: 1
    }
  }
};

export const statusListConfig = {
  title: 'Status List Configuration',
  type: 'object',
  required: ['type', 'suiteName', 'statusPurpose'],
  additionalProperties: false,
  properties: {
    type: {
      type: 'string',
      // supported types in this version
      enum: ['StatusList2021', 'RevocationList2020']
    },
    suiteName,
    statusPurpose: {
      type: 'string',
      // supported status types in this version
      enum: ['revocation', 'suspension']
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
          minItems: 1,
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

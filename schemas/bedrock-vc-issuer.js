/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
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
      enum: ['Ed25519Signature2020', 'Ed25519Signature2018']
    }
  }
};

export const statusListConfig = {
  title: 'Status List Configuration',
  type: 'object',
  required: ['suiteName', 'statusPurpose'],
  additionalProperties: false,
  properties: {
    suiteName: {
      type: 'string',
      // supported suites in this version
      enum: ['Ed25519Signature2020', 'Ed25519Signature2018']
    },
    statusPurpose: {
      type: 'string',
      // supported status types in this version
      enum: ['revocation']
    }
  }
};

export const statusListOptions = {
  title: 'Status List Options',
  type: 'array',
  minItems: 1,
  items: {
    statusListConfig
  }
};

export const issueCredentialBody = {
  title: 'Issue Credential',
  type: 'object',
  required: ['credential'],
  additionalProperties: false,
  properties: {
    options: {
      // FIXME: make restricted
      type: 'object'
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
      additionalProperties: false,
      properties: {
        type: {
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

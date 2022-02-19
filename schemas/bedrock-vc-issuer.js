/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
export const issueOptions = {
  title: 'Issue Options',
  type: 'object',
  required: ['suiteName'],
  additionalProperties: false,
  properties: {
    suiteName: {
      type: 'string'
    }
  }
};

export const statusListConfig = {
  title: 'Status List Configuration',
  type: 'object',
  required: ['suiteName', 'statusType'],
  additionalProperties: false,
  properties: {
    suiteName: {
      type: 'string'
    },
    statusType: {
      type: 'string'
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

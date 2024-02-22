/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
export const DEFAULT_BLOCK_COUNT = 4096;
export const DEFAULT_BLOCK_SIZE = 32;

// default `TerseBitstringStatusList` list count is 32-bit integer size
export const DEFAULT_TERSE_LIST_COUNT = 0x100000000;

// max list size is DEFAULT_BLOCK_COUNT * DEFAULT_BLOCK_SIZE = 131072
export const MAX_LIST_SIZE = DEFAULT_BLOCK_COUNT * DEFAULT_BLOCK_SIZE;

// maximum number of lists this software can keep track of (applies only to
// status list configurations where the number of lists is limited)
export const MAX_LIST_COUNT = Number.MAX_SAFE_INTEGER;

export const MAX_STATUS_LIST_OPTIONS = 1;

export const serviceType = 'vc-issuer';

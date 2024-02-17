/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
// max list size is MAX_BLOCK_COUNT * MAX_BLOCK_SIZE = 131072
export const MAX_BLOCK_COUNT = 4096;
export const MAX_BLOCK_SIZE = 32;

// maximum number of lists this software can keep track of (applies only to
// status list configurations where the number of lists is limited)
export const MAX_LIST_COUNT = Number.MAX_SAFE_INTEGER;

export const serviceType = 'vc-issuer';

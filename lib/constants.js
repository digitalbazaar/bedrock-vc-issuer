/*!
 * Copyright (c) 2024-2025 Digital Bazaar, Inc. All rights reserved.
 */
// maximum number of cryptosuites to be used in a proof set
export const MAX_CRYPTOSUITE_OPTIONS = 10;

// max list size is 2^26, which is the largest size a totally random,
// unencrypted list can be (8MiB) without breaking the max 10MiB storage
// barrier for a single VC -- leaving 2MiB of space for other information
// beyond the list in a status list credential
// 2^26/2^3/2^10/2^10=2^3 = 8
// 67108864 bits / 8 / 1024 / 1024 = 8MiB
export const MAX_LIST_SIZE = 67108864;
// 2^5 = 32; max block size should be small to increase concurrency
export const MAX_BLOCK_SIZE = 32;
// max block count is MAX_LIST_SIZE / MAX_BLOCK_SIZE
// 2^21 = 2^26/2^5 = 2097152
export const MAX_BLOCK_COUNT = 2097152;

// maximum number of lists this software can keep track of (applies only to
// status list configurations where the number of lists is limited)
export const MAX_LIST_COUNT = Number.MAX_SAFE_INTEGER;

export const MAX_STATUS_LIST_OPTIONS = 1;

// default `TerseBitstringStatusList` list count is 32-bit integer size
// divided by default list size = 2^32/2^26 = 2^6 = 64; each list will
// be 2^26 in size = 67108864
export const DEFAULT_TERSE_LIST_COUNT = 64;

// default is only 4096 for smaller use cases of ~100K populations
// where 4096 * 32 = 131072
export const DEFAULT_BLOCK_COUNT = 4096;
export const DEFAULT_BLOCK_SIZE = MAX_BLOCK_SIZE;

// default list size is DEFAULT_BLOCK_COUNT * DEFAULT_BLOCK_SIZE
// = 2^17 = 131072
export const DEFAULT_LIST_SIZE = DEFAULT_BLOCK_COUNT * DEFAULT_BLOCK_SIZE;

export const serviceType = 'vc-issuer';

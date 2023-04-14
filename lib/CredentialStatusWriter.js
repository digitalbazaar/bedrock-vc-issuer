/*!
 * Copyright (c) 2020-2023 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import {Bitstring} from '@digitalbazaar/bitstring';
import {createRequire} from 'node:module';
import {getCredentialStatusInfo} from './helpers.js';
import {ListManager} from './ListManager.js';
const require = createRequire(import.meta.url);
const LRU = require('lru-cache');

// TODO: make cache sizes configurable
const MAX_SHARD_QUEUES = 1000;
const SHARD_QUEUE_CACHE = new LRU({max: MAX_SHARD_QUEUES});
const MAX_SHARD_QUEUE_SIZE = 10;

/* Notes: See ListManager.js for more details.

Algorithms:

Note: All of the following algorithms are designed such that they don't need
atomicity, but that they are instead safely "continuable" from any point of
failure. The system continues to make progress even if a single worker
fails, as long as that worker does not create corrupt state. The algorithms
do not enable recovery from corrupt state.

main: The process for issuing a VC with an assigned an index.

0. The worker sets up an in-memory set of list shards (LS), where LS includes
  an SL ID, SL sequence number, BAD, and IAD.
1. Create a CredentialStatusWriter instance `writer`.
2. While a VC has not been successfully written to the database (EDV):
  2.1. Call writer.write(VC).
  2.2. Sign the VC.
  2.3. Attempt to insert the VC in to the database (EDV).
    2.3.1. Note: The database must have a unique index on SL ID + SL index.
  2.4. If a duplicate error occurs, first make sure it is a duplicate error
    due to SL ID + SL index, and if so, loop, otherwise throw.
2. VC has been successfully issued, return it immediately, the receiver of
  the VC response does not need to wait for the following steps to finish.
3. Call writer.finish().
4. Return.

writer.write(VC): Writes credential status information to the
  given VC, overwriting it if it is already present. To be called when
  trying to issue a VC or after a failure to write a VC to the database (EDV)
  because of a duplicate error.

1. If an LS has been assigned to the writer instance (then a duplicate
  error for the VC is being handled):
  1.1. Read the IAD.
  1.2. If the IAD's SL sequence matches the one from the LS and the IAD's
    latest assigned index value is behind the index in the VC's
    `credentialStatus` field:
    1.2.1. Update the latest assigned index value.
    1.2.2. CW update the IAD.
    1.2.3. If no conflict, add the LS to the in-memory set for reuse (Note
      that this is the only case where the LS is added back to the set,
      otherwise, it is presumed that another worker is using it).
  1.3. Clear the LS from the instance.
2. If the in-memory set is empty:
  2.1. Create a ListManager instance `listManager`.
  2.2. Call listManager.getShard() and store result in the instance.
3. Otherwise, remove an LS from the set and store it in the instance.
4. Use the SL ID and the IAD from the LS to add the SL ID and the next
  unassigned SL index to a VC's credential status section.

writer.finish():

1. Increment instance's IAD's latest index value.
2. CW update IAD. If conflict, ignore.
3. If IAD has had all indexes assigned:
  3.1. Read BAD. If its SL sequence number does not match, return.
  3.2. If the BAD's bitstring has already been updated, return.
  3.3. Update BAD's bitstring and CW update the BAD. If conflict, ignore.
4. Otherwise, add LS back to in-memory set.
5. Clear instance's LS.
*/
export class CredentialStatusWriter {
  constructor({
    slcsBaseUrl, documentLoader, documentStore,
    issuer, statusListConfig, suite
  } = {}) {
    assert.string(slcsBaseUrl, 'slcsBaseUrl');
    assert.func(documentLoader, 'documentLoader');
    assert.object(documentStore, 'documentStore');
    assert.string(issuer, 'issuer');
    assert.object(statusListConfig, 'statusListConfig');
    assert.object(suite, 'suite');
    if(!slcsBaseUrl) {
      throw new TypeError('"slcsBaseUrl" must be a non-empty string.');
    }
    if(!issuer) {
      throw new TypeError('"issuer" must be a non-empty string.');
    }
    this.slcsBaseUrl = slcsBaseUrl;
    this.documentLoader = documentLoader;
    this.documentStore = documentStore;
    this.issuer = issuer;
    this.statusListConfig = statusListConfig;
    this.suite = suite;
    this.listShard = null;
  }

  async write({credential} = {}) {
    assert.object(credential, 'credential');

    const {documentStore: {serviceObjectId}, statusListConfig} = this;
    let shardQueue = SHARD_QUEUE_CACHE.get(serviceObjectId);
    if(!shardQueue) {
      shardQueue = [];
      SHARD_QUEUE_CACHE.set(serviceObjectId, shardQueue);
    }

    // get `edvClient` directly; do not use cache in `documentStore` to ensure
    // latest docs are used
    const {documentStore: {edvClient}} = this;

    // 1. If an LS has been assigned to the writer instance (then a duplicate
    // error for the VC is being handled):
    const {listShard} = this;
    let existingCredentialStatus;
    if(listShard) {
      const {statusListIndex, credentialStatus} = getCredentialStatusInfo(
        {credential, statusListConfig});
      existingCredentialStatus = credentialStatus;

      // 1.1. Read the IAD.
      const {indexAssignmentDoc, item: {slSequence}} = listShard;
      const doc = await edvClient.get({id: indexAssignmentDoc.id});
      listShard.indexAssignmentDoc = doc;

      // 1.2. If the IAD's SL sequence matches the one from the LS and the
      //   IAD's latest assigned index value is behind the index in the VC's
      //   `credentialStatus` field:
      const localIndex = _getLocalIndex({listShard, statusListIndex});

      // the nextLocalIndex must be greater than the localIndex from the
      // credentialStatus
      if(doc.content.slSequence === slSequence &&
        doc.content.nextLocalIndex <= localIndex) {
        // 1.2.1. Update the latest assigned index value.
        doc.content.nextLocalIndex = localIndex + 1;
        // 1.2.2. CW update the IAD.
        try {
          await edvClient.update({doc});
          if(shardQueue.length < MAX_SHARD_QUEUE_SIZE) {
            shardQueue.push(listShard);
          }
        } catch(e) {
          // ignore conflict error, throw others
          if(e.name !== 'InvalidStateError') {
            throw e;
          }
        }
      }

      // 1.3. Clear the LS from the instance.
      this.listShard = null;
    }

    // 2. If the in-memory set is empty:
    if(shardQueue.length === 0) {
      // 2.1. Create a ListManager instance `listManager`.
      // 2.2. Call listManager.getShard() and store result in the instance.
      const {
        slcsBaseUrl, documentLoader, documentStore, issuer, suite
      } = this;
      const listManager = new ListManager({
        id: _createListManagerId({statusListConfig}),
        slcsBaseUrl,
        documentLoader,
        documentStore,
        issuer,
        statusListConfig,
        suite
      });
      this.listShard = await listManager.getShard();
    } else {
      // 3. Otherwise, remove an LS from the set and store it in the
      // instance.
      this.listShard = shardQueue.shift();
    }

    // 4. Use the SL ID and the IAD from the LS to add the SL ID and the next
    //   unassigned SL index to a VC's credential status section.
    const {
      item: {statusListCredential},
    } = this.listShard;
    const statusListIndex = _getListIndex({listShard: this.listShard});
    this._upsertStatusEntry({
      credential, statusListCredential, statusListIndex,
      credentialStatus: existingCredentialStatus
    });
  }

  async finish() {
    const {listShard} = this;
    if(!listShard) {
      // `finish` should never be called when no `listShard` is available
      throw new Error(
        'Invalid state error; "finish()" must only be called after "write()".');
    }

    // get `edvClient` directly; do not use cache in `documentStore` to ensure
    // latest docs are used
    const {documentStore: {edvClient, serviceObjectId}} = this;

    // 1. Increment instance's IAD's latest index value.
    const {
      indexAssignmentDoc,
      blockIndex,
      blockAssignmentDoc: {content: {blockSize}}
    } = listShard;
    const {content: iadContent} = indexAssignmentDoc;
    // 2. CW update IAD. If conflict, ignore.
    try {
      iadContent.nextLocalIndex++;
      listShard.indexAssignmentDoc = await edvClient.update(
        {doc: indexAssignmentDoc});
    } catch(e) {
      // ignore conflict error, throw others
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
    }
    // 3. If IAD has had all indexes assigned:
    if(iadContent.nextLocalIndex === blockSize) {
      // 3.1. Read BAD. If its SL sequence number does not match, return.
      const {item: {slSequence}} = listShard;
      const blockAssignmentDoc = await edvClient.get(
        {id: listShard.blockAssignmentDoc.id});
      if(blockAssignmentDoc.content.slSequence !== slSequence) {
        return;
      }
      // 3.2. If the BAD's bitstring has already been updated, return.
      const {assignedBlocks} = blockAssignmentDoc.content;
      const bs = await Bitstring.decodeBits({encoded: assignedBlocks});
      if(bs.get(blockIndex)) {
        return;
      }
      // 3.3. Update BAD's bitstring and CW update the BAD. If conflict, ignore.
      bs.set(blockIndex, true);
      blockAssignmentDoc.content.assignedBlocks = await bs.encodeBits();
      try {
        await edvClient.update({doc: blockAssignmentDoc});
      } catch(e) {
        // ignore conflict error, throw others
        if(e.name !== 'InvalidStateError') {
          throw e;
        }
      }
    } else {
      // 4. Otherwise, add LS back to in-memory set.
      let shardQueue = SHARD_QUEUE_CACHE.get(serviceObjectId);
      if(!shardQueue) {
        shardQueue = [];
        SHARD_QUEUE_CACHE.set(serviceObjectId, shardQueue);
      }
      shardQueue.push(listShard);
    }
    // 5. Clear instance's LS.
    this.listShard = null;
  }

  async exists({credential} = {}) {
    assert.object(credential, 'credential');
    const count = await this.documentStore.edvClient.count({
      equals: {'content.credentialStatus.id': credential.credentialStatus.id}
    });
    return count !== 0;
  }

  _upsertStatusEntry({
    credential, statusListCredential, statusListIndex, credentialStatus
  }) {
    const {type, statusPurpose} = this.statusListConfig;
    const existing = !!credentialStatus;
    if(!existing) {
      // create new credential status
      credentialStatus = {};
    }

    credentialStatus.id = `${statusListCredential}#${statusListIndex}`;

    if(type === 'RevocationList2020') {
      credentialStatus.type = 'RevocationList2020Status';
      credentialStatus.revocationListCredential = statusListCredential;
      credentialStatus.revocationListIndex = `${statusListIndex}`;
    } else {
      // assume `StatusList2021`
      credentialStatus.type = 'StatusList2021Entry';
      credentialStatus.statusListCredential = statusListCredential;
      credentialStatus.statusListIndex = `${statusListIndex}`;
      credentialStatus.statusPurpose = statusPurpose;
    }

    // add credential status if it did not already exist
    if(!existing) {
      if(Array.isArray(credential.credentialStatus)) {
        credential.credentialStatus.push(credentialStatus);
      } else if(typeof credential.credentialStatus === 'object') {
        credential.credentialStatus = [
          credential.credentialStatus, credentialStatus
        ];
      } else {
        // presume no status set yet
        credential.credentialStatus = credentialStatus;
      }
    }
  }
}

function _getListIndex({listShard}) {
  const {
    blockIndex,
    indexAssignmentDoc: {content: {nextLocalIndex}},
    blockAssignmentDoc: {content: {blockSize}}
  } = listShard;
  return blockIndex * blockSize + nextLocalIndex;
}

function _getLocalIndex({listShard, statusListIndex}) {
  const {blockAssignmentDoc: {content: {blockSize}}} = listShard;
  return statusListIndex % blockSize;
}

function _createListManagerId({statusListConfig}) {
  const {type, statusPurpose} = statusListConfig;
  if(type === 'RevocationList2020') {
    // hard-coded legacy ID
    return 'urn:vc-issuer:rl2020-lm';
  }

  // parameterized ID for modern status list (2021)
  return `urn:vc-issuer:${encodeURIComponent(type)}:` +
    `${encodeURIComponent(statusPurpose)}:ListManager`;
}

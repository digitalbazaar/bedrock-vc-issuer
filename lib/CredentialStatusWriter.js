/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import {Bitstring} from '@digitalbazaar/bitstring';
import {createRequire} from 'node:module';
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
    latest assigned index value is behind the index used to
    generate status entries in the VC's `credentialStatus` field:
    1.2.1. Update the latest assigned index value (max of `blockSize`).
    1.2.2. CW update the IAD.
    1.2.3. If no conflict, add the LS to the in-memory set for reuse (Note
      that this is the only case where the LS is added back to the set,
      otherwise, it is presumed that another worker is using it).
  1.3. Remove any status entries generated using the previous index value.
  1.4. Clear the LS from the instance.
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
  constructor({statusListConfig, documentLoader, edvClient, listSource} = {}) {
    assert.object(statusListConfig, 'statusListConfig');
    assert.func(documentLoader, 'documentLoader');
    assert.object(edvClient, 'edvClient');
    assert.object(listSource, 'listSource');
    this.statusListConfig = statusListConfig;
    this.documentLoader = documentLoader;
    this.edvClient = edvClient;
    this.listSource = listSource;
    this.listShard = null;
  }

  async write({credential, duplicateResult} = {}) {
    assert.object(credential, 'credential');
    console.log('******** duplicateResult', duplicateResult);

    const {edvClient, statusListConfig, listShard} = this;
    const {indexAllocator} = statusListConfig;
    let shardQueue = SHARD_QUEUE_CACHE.get(indexAllocator);
    if(!shardQueue) {
      shardQueue = [];
      SHARD_QUEUE_CACHE.set(indexAllocator, shardQueue);
    }

    // 1. If an LS has been assigned to the writer instance (then a duplicate
    // error for the VC is being handled):
    if(listShard) {
      // 1.1. Read the IAD.
      const {
        indexAssignmentDoc,
        blockAssignmentDoc: {content: {blockSize}},
        item: {slSequence}
      } = listShard;
      const doc = await edvClient.get({id: indexAssignmentDoc.id});
      listShard.indexAssignmentDoc = doc;

      // 1.2. If the IAD's SL sequence matches the one from the LS and the
      //   IAD's latest assigned index value is behind the index used to
      //   generate status entries in the VC's `credentialStatus` field:
      const {localIndex} = duplicateResult;
      // the nextLocalIndex must be greater than the localIndex from the
      // credentialStatus
      if(doc.content.slSequence === slSequence &&
        doc.content.nextLocalIndex <= localIndex) {
        /* Note: This step works because the issuance storage system will
        prevent duplicate status indexes from being issued for the same SLC
        for different VCs. If concurrent processes issue with the same SLC and
        index, only one can be successful -- and success does not even require
        the IAD to be updated (a failure could occur before it is updated and
        this is recoverable here). This process will increment the IAD's local
        index counter to one more than whatever the VC indicates caused a
        duplicate (with a max of `blockSize`), and ensure it is therefore
        re-sync'd. */

        // TODO: try to share most of `finish()` code here

        // 1.2.1. Update the latest assigned index value (max of `blockSize`).
        doc.content.nextLocalIndex = Math.min(blockSize, localIndex + 1);
        // 1.2.2. CW update the IAD.
        try {
          await edvClient.update({doc});
          // re-queue the shard if there are indexes left
          if(doc.content.nextLocalIndex < blockSize &&
            shardQueue.length < MAX_SHARD_QUEUE_SIZE) {
            shardQueue.push(listShard);
          }
        } catch(e) {
          // ignore conflict error, throw others
          if(e.name !== 'InvalidStateError') {
            throw e;
          }
        }
      }

      // 1.3. Remove any status entries generated using the previous index
      //   value.
      this._removeDuplicateStatusEntries({credential, duplicateResult});

      // 1.4. Clear the LS from the instance.
      this.listShard = null;
    }

    // 2. If the in-memory set is empty:
    if(shardQueue.length === 0) {
      // 2.1. Create a ListManager instance `listManager`.
      // 2.2. Call listManager.getShard() and store result in the instance.
      const {documentLoader, edvClient, listSource} = this;
      const listManager = new ListManager({
        statusListConfig,
        documentLoader,
        edvClient,
        listSource
      });
      this.listShard = await listManager.getShard();
    } else {
      // 3. Otherwise, remove an LS from the set and store it in the
      // instance.
      this.listShard = shardQueue.shift();
    }

    // 4. Use LS to get the status lists metadata and IAD. Use the SL metadata
    //   and the next unassigned SL index from the IAD add the appropriate
    //   information (based on list type) to a VC's credential status section.
    const {
      blockIndex,
      blockAssignmentDoc: {content: {blockSize}},
      indexAssignmentDoc: {content: {nextLocalIndex: localIndex}},
      item: {statusLists}
    } = this.listShard;
    const statusListIndex = blockIndex * blockSize + localIndex;
    // add a status entry for each status list from `item`
    const result = {
      localIndex,
      statusEntries: statusLists.map(statusList =>
        this._addStatusEntry({credential, statusList, statusListIndex}))
    };
    return result;
  }

  async finish() {
    const {edvClient, listShard} = this;
    if(!listShard) {
      // `finish` should never be called when no `listShard` is available
      throw new Error(
        'Invalid state error; "finish()" must only be called after "write()".');
    }

    // 1. Increment instance's IAD's latest index value.
    const {
      indexAssignmentDoc,
      blockIndex,
      blockAssignmentDoc: {content: {blockSize}}
    } = listShard;
    const {content: iadContent} = indexAssignmentDoc;
    // 2. CW update IAD. If conflict, ignore.
    try {
      iadContent.nextLocalIndex = Math.min(
        blockSize, iadContent.nextLocalIndex + 1);
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
      const buffer = await Bitstring.decodeBits({encoded: assignedBlocks});
      const bs = new Bitstring({buffer});
      if(bs.get(blockIndex)) {
        return;
      }
      // 3.3. Update BAD's bitstring and CW update the BAD. If conflict, ignore.
      bs.set(blockIndex, true);
      blockAssignmentDoc.content.assignedBlocks = await bs.encodeBits();
      blockAssignmentDoc.content.assignedBlockCount++;
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
      const {statusListConfig: {indexAllocator}} = this;
      let shardQueue = SHARD_QUEUE_CACHE.get(indexAllocator);
      if(!shardQueue) {
        shardQueue = [];
        SHARD_QUEUE_CACHE.set(indexAllocator, shardQueue);
      }
      shardQueue.push(listShard);
    }
    // 5. Clear instance's LS.
    this.listShard = null;
  }

  async exists({statusResult} = {}) {
    assert.object(statusResult, 'statusResult');
    assert.array(statusResult.statusEntries, 'statusResult.statusEntries');
    // check every entry's `meta`'s `credentialStatus.id` for duplicates
    const counts = await Promise.all(statusResult.statusEntries.map(
      async ({meta: {credentialStatus}}) => this.edvClient.count({
        equals: {'meta.credentialStatus.id': credentialStatus.id}
      })));
    return counts.some(count => count !== 0);
  }

  _addStatusEntry({credential, statusList, statusListIndex}) {
    const {type, statusPurpose, options} = this.statusListConfig;

    // set SLC ID to the ID of the status list as they are one in the same
    const statusListCredential = statusList.id;

    const meta = {
      // include all status information in `meta`
      credentialStatus: {
        id: `${statusListCredential}#${statusListIndex}`,
        // `type` is set below
        type: undefined,
        statusListCredential,
        // this is the index of the VC's status within the status list
        statusListIndex,
        statusPurpose
      }
    };
    // include `listIndex` as `listNumber` (to avoid confusion with
    // `statusListIndex` which refers to the index of the status for the VC)
    // ...if present (used, for example, for terse lists)
    if(statusList.listIndex !== undefined) {
      meta.credentialStatus.listNumber = statusList.listIndex;
    }

    // include all or subset of status information (depending on type)
    const credentialStatus = {};
    if(type === 'RevocationList2020') {
      credentialStatus.id = meta.credentialStatus.id;
      credentialStatus.type = 'RevocationList2020Status';
      credentialStatus.revocationListCredential = statusListCredential;
      credentialStatus.revocationListIndex = `${statusListIndex}`;
    } else if(type === 'StatusList2021') {
      credentialStatus.id = meta.credentialStatus.id;
      credentialStatus.type = 'StatusList2021Entry';
      credentialStatus.statusListCredential = statusListCredential;
      credentialStatus.statusListIndex = `${statusListIndex}`;
      credentialStatus.statusPurpose = statusPurpose;
    } else if(type === 'BitstringStatusList') {
      credentialStatus.id = meta.credentialStatus.id;
      credentialStatus.type = 'BitstringStatusListEntry';
      credentialStatus.statusListCredential = statusListCredential;
      credentialStatus.statusListIndex = `${statusListIndex}`;
      credentialStatus.statusPurpose = statusPurpose;
    } else {
      // assume `TerseBitstringStatusList`
      credentialStatus.type = 'TerseBitstringStatusListEntry';
      // this type of status list uses `terseStatusListIndex` in VCs instead,
      // which is expressed as an offset into total list index space instead of
      // into the individual status list
      const listSize = options.blockCount * options.blockSize;
      const offset = statusList.listIndex * listSize + statusListIndex;
      // the property value is an integer not a string
      credentialStatus.terseStatusListIndex = offset;
      meta.credentialStatus.terseStatusListIndex = offset;

      // FIXME: remove once `TerseBitstringStatusList` context is installed
      credentialStatus.type = 'StatusList2021Entry';
      credentialStatus.statusListIndex = `${statusListIndex}`;
      delete credentialStatus.terseStatusListIndex;
    }
    // ensure `meta.credentialStatus.type` is set
    meta.credentialStatus.type = credentialStatus.type;

    // add credential status if it did not already exist
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

    return {meta, credentialStatus};
  }

  _removeDuplicateStatusEntries({credential, duplicateResult}) {
    // only one credential status, assume it matches and remove it
    if(!Array.isArray(credential.credentialStatus)) {
      delete credential.credentialStatus;
      return;
    }

    // remove only the matching duplicate entries
    const duplicates = duplicateResult.statusEntries.map(
      ({credentialStatus}) => credentialStatus);
    credential.credentialStatus = credential.credentialStatus.filter(
      e => !duplicates.includes(e));
  }
}

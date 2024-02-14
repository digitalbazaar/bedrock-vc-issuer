/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import {Bitstring} from '@digitalbazaar/bitstring';
import {v4 as uuid} from 'uuid';

// FIXME: add `_readBlockAssignmentDoc()`

/* See: ListManager for more design notes.

this.selectShard(LMD, activeBADs): Select an IAD to use for assigning indexes:

1. Select an IAD at random from the cached BAD blocks with unassigned indexes:
  1.1. Get total number of unassigned blocks and choose randomly.
  1.2. Use choice to find chosen IAD and block index.
2. CW create the IAD if it does not exist or if IAD's SL sequence number
  is behind the one associated with the BAD, CW update the IAD to reset it.
2.1. If a conflict or duplicate error is thrown then another worker has chosen
  the same IAD; rethrow the error.
3. If the IAD's SL sequence number is ahead, return `null`.
4. If the IAD's indexes have all been assigned:
  4.1. CW update the BAD to indicate the IAD block has been assigned.
  4.2. If conflict, ignore.
  4.3. Return `null`. Note: A future optimization might be to loop
    again and make a *different* choice, but the code must ensure
    there are more choices to be made.
5. Return SL ID, SL sequence number, BAD, and IAD.

*/

export class IndexAllocationCache {
  // FIXME: expose function to read records instead of passing here
  constructor({edvClient, records} = {}) {
    assert.object(edvClient, 'edvClient');
    this.edvClient = edvClient;
    this.records = records;//[];
  }

  async outOfSync() {
    // if any record has a BAD SL sequence number that is greater than the
    // LMD item SL sequence number, then the cache is out of sync
    const {records} = this;
    return records.some(({blockAssignmentDoc: {content}, item}) =>
      content.slSequence > item.slSequence);
  }

  async selectShard() {
    const {edvClient, records} = this;

    // 1. Select an IAD at random from the BAD blocks with unassigned indexes:
    //   1.1. Get total number of unassigned blocks and choose randomly.
    //   1.2. Use choice to find chosen IAD and block index.
    const choice = await _chooseRandom({records});

    // 2. CW create the IAD if it does not exist or if IAD's SL sequence number
    //   is behind the one associated with the BAD, CW update the IAD to reset
    //   it.
    const {blockIndex, blockAssignmentDoc} = choice;
    const {content: {slSequence}} = blockAssignmentDoc;
    const blockAssignmentDocId = blockAssignmentDoc.content.id;
    let {indexAssignmentDoc} = await this._getIndexAssignmentDoc(
      {blockAssignmentDocId, blockIndex, slSequence});
    if(indexAssignmentDoc.content.slSequence < slSequence) {
      // TODO: add a function for resetting an IAD
      indexAssignmentDoc.content.slSequence = slSequence;
      indexAssignmentDoc.content.nextLocalIndex = 0;
      indexAssignmentDoc = await edvClient.update({doc: indexAssignmentDoc});
    }
    // 2.1. If a conflict or duplicate error is thrown then another worker has
    //   chosen the same IAD; rethrow the error. (automatic)

    // 3. If the IAD's SL sequence number is ahead, return `null`.
    if(indexAssignmentDoc.content.slSequence > slSequence) {
      return null;
    }

    // 4. If the IAD's indexes have all been assigned:
    if(indexAssignmentDoc.content.nextLocalIndex ===
      blockAssignmentDoc.content.blockSize) {
      // 4.1. CW update the BAD to indicate the IAD block has been assigned.
      try {
        const {assignedBlocks} = blockAssignmentDoc.content;
        const buffer = await Bitstring.decodeBits({encoded: assignedBlocks});
        const bs = new Bitstring({buffer});
        bs.set(indexAssignmentDoc.meta.blockIndex, true);
        blockAssignmentDoc.content.assignedBlocks = await bs.encodeBits();
        blockAssignmentDoc.content.assignedBlockCount++;
        await edvClient.update({doc: blockAssignmentDoc});
      } catch(e) {
        if(e.name !== 'InvalidStateError') {
          throw e;
        }
        // 4.2. If conflict, ignore.
      }
      // 4.3. Return `null`. Note: A future optimization might be to loop
      //   again and make a *different* choice, but the code must ensure
      //   there are more choices to be made.
      return null;
    }

    // 5. Return SL ID, SL sequence number, BAD, and IAD.
    return {...choice, indexAssignmentDoc};
  }

  // FIXME: determine how to expose for use in `ListManager`
  // read BAD contents referenced from LM doc item into a cache record
  async _readBlockAssignmentDoc({item}) {
    const {edvClient, statusListConfig} = this;

    // executes step 1.2.1 of `_readActiveBlockAssignmentDocs()`
    let blockAssignmentDoc;
    while(!blockAssignmentDoc) {
      try {
        blockAssignmentDoc = await edvClient.get({
          id: item.blockAssignmentEdvDocId
        });
      } catch(e) {
        if(e.name !== 'NotFoundError') {
          throw e;
        }

        // next, lazily create BAD
        const type = 'StatusListBlockAssignmentDocument';
        const doc = {
          id: item.blockAssignmentEdvDocId,
          content: {
            id: `urn:uuid:${uuid()}`,
            type
          },
          meta: {type}
        };
        await _resetBlockAssignmentDoc({
          content: doc.content, slSequence: item.slSequence, statusListConfig
        });
        try {
          blockAssignmentDoc = await edvClient.update({doc});
        } catch(e) {
          if(e.name !== 'DuplicateError') {
            throw e;
          }
          // duplicate, ignore and loop to read doc
        }
      }
    }

    // executes step 1.2.2 of `_readActiveBlockAssignmentDocs()`
    const cacheRecord = {blockAssignmentDoc, item};
    await this._syncCacheRecord(cacheRecord);
    return cacheRecord;
  }

  async _getIndexAssignmentDoc({
    blockAssignmentDocId, blockIndex, slSequence
  }) {
    const {edvClient} = this;

    // try to find existing index assignment doc
    const equals = {
      'meta.blockAssignmentDocId': blockAssignmentDocId,
      'meta.blockIndex': blockIndex
    };

    // Note: This implementation is notably different from the
    // `_getListManagementDoc` because when duplicate or conflict errors arise,
    // we want to throw them, not ignore and read.
    const {documents} = await edvClient.find({equals, limit: 1});
    if(documents.length === 0) {
      const type = 'StatusListIndexAssignmentDocument';
      let indexAssignmentDoc = {
        id: await edvClient.generateId(),
        content: {
          id: `urn:uuid:${uuid()}`,
          type,
          slSequence,
          nextLocalIndex: 0
        },
        meta: {
          type,
          blockAssignmentDocId,
          blockIndex
        }
      };
      indexAssignmentDoc = await edvClient.update({doc: indexAssignmentDoc});
      return {indexAssignmentDoc};
    } else {
      const [indexAssignmentDoc] = documents;
      return {indexAssignmentDoc};
    }
  }

  // ensure cache record BAD contents are in sync with LM doc item
  async _syncCacheRecord(cacheRecord) {
    // 1.2.2. If any BAD has an SL sequence number that is behind an LMD item,
    //   CW update it. If conflict, read the BAD.
    if(cacheRecord.blockAssignmentDoc.content.slSequence >=
      cacheRecord.item.slSequence) {
      return cacheRecord;
    }

    const {edvClient, statusListConfig} = this;

    try {
      // reset block assignment doc
      const {content} = cacheRecord.blockAssignmentDoc;
      await _resetBlockAssignmentDoc({
        content, slSequence: cacheRecord.item.slSequence, statusListConfig
      });
      cacheRecord.blockAssignmentDoc = await edvClient.update({
        doc: cacheRecord.blockAssignmentDoc
      });
    } catch(e) {
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
      cacheRecord.blockAssignmentDoc = await edvClient.get({
        id: cacheRecord.blockAssignmentDoc.id
      });
    }

    return cacheRecord;
  }
}

async function _chooseRandom({records}) {
  // get the total number of unassigned blocks
  const unassignedBlockCount = records.reduce((count, x) => {
    const {blockAssignmentDoc: {content}} = x;
    return count + content.blockCount - content.assignedBlockCount;
  }, 0);
  let choice = Math.floor(Math.random() * unassignedBlockCount);
  // choice is based on total unassigned blocks, now must map the choice
  // to an actual block index
  let blockIndex = 0;
  // note: `records` is assumed to never be empty per the design
  for(const cacheRecord of records) {
    const {blockAssignmentDoc: {content}} = cacheRecord;
    // FIXME: improve comments for maintenance and understandability
    const unassignedCount = content.blockCount - content.assignedBlockCount;
    if(choice >= unassignedCount) {
      // chosen block is not in this list, remove unassigned blocks from
      // the list from the choice
      choice -= unassignedCount;
    } else {
      // chosen block is in this list, determine specific block index
      const buffer = await Bitstring.decodeBits(
        {encoded: content.assignedBlocks});
      const bs = new Bitstring({buffer});
      while(choice > 0) {
        if(!bs.get(blockIndex)) {
          // block is not assigned, reduce choice
          choice--;
        }
        blockIndex++;
      }
      return {...cacheRecord, blockIndex};
    }
  }
}

// FIXME: either consolidate or only use in this file not also `ListManager`
async function _resetBlockAssignmentDoc({
  content, slSequence, statusListConfig
}) {
  content.slSequence = slSequence;
  content.blockCount = statusListConfig.options.blockCount;
  content.blockSize = statusListConfig.options.blockSize;
  // TODO: optimize by using string from config or static var
  const bs = new Bitstring({length: content.blockCount});
  content.assignedBlocks = await bs.encodeBits();
  content.assignedBlockCount = 0;
}

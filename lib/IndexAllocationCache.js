/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import {Bitstring} from '@digitalbazaar/bitstring';
import {v4 as uuid} from 'uuid';

/* See: ListManager for more design notes.

this.populate(LMD "active" set items): Reads all active BADs to enable
  choosing an IAD.

1. Read all BADs associated with the given items.
  1.1. If any BAD does not exist, CW create it.
  1.2. If any BAD has an SL sequence number that is behind an LMD item,
    CW update it. If conflict, read the BAD.

this.rotate(LMD block assignment): Rotates any "active" items associated with
  BADs that have fully-assigned blocks to the "inactive" set without writing
  the result to storage:

1. Get all cache records associated with BADs that have fully assigned blocks
  of indexes.
2. If any fully-assigned cache records are found:
  2.1. Add the fully-assigned items to the "inactive" set.
  2.2. Remove the fully-assigned items from the "active" set.
  2.3. Remove the fully-assigned items from the cache records.
3. Return any fully-assigned cache records.

this.selectShard(): Select an IAD to use for assigning indexes:

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
  constructor({edvClient, statusListConfig} = {}) {
    assert.object(edvClient, 'edvClient');
    this.edvClient = edvClient;
    this.records = [];
    this.statusListConfig = statusListConfig;
    this._outOfSync = false;
  }

  // return if the cache is out of sync with storage
  outOfSync() {
    // if out-of-sync previously detected, return it
    if(this._outOfSync) {
      return true;
    }
    // if any record has a BAD SL sequence number that is greater than the
    // LMD item SL sequence number, then the cache is out of sync
    const {records} = this;
    this._outOfSync = records.some(({blockAssignmentDoc: {content}, item}) =>
      content.slSequence > item.slSequence);
    return this._outOfSync;
  }

  // populate this cache from the given items
  async populate({items} = {}) {
    this._outOfSync = false;
    this.records = await Promise.all(items.map(
      item => this._readBlockAssignmentDoc({item})));
  }

  // reset and store the block assignment doc associated with cache `record`
  async resetBlockAssignmentDoc({record} = {}) {
    const {edvClient, statusListConfig} = this;
    const {content} = record.blockAssignmentDoc;
    await _initBlockAssignmentDoc({
      content, slSequence: record.item.slSequence, statusListConfig
    });
    record.blockAssignmentDoc = await edvClient.update(
      {doc: record.blockAssignmentDoc});
  }

  // rotate fully-assigned items out of "active" set into "inactive" set
  rotate({blockAssignment} = {}) {
    // 1. Get all cache records associated with BADs that have fully assigned
    //   blocks of indexes.
    const fullyAssigned = this.records.filter(
      ({blockAssignmentDoc: {content}}) =>
        content.assignedBlockCount === content.blockCount);
    // 2. If any fully-assigned cache records are found:
    if(fullyAssigned.length > 0) {
      // 2.1. Add the fully-assigned items to the "inactive" set.
      const items = fullyAssigned.map(({item}) => item);
      blockAssignment.inactive.push(...items);
      // 2.2. Remove the fully-assigned items from "active" set.
      blockAssignment.active = blockAssignment.active.filter(
        item => !items.includes(item));
      // 2.3. Remove the fully-assigned items from the cache records.
      this.records = this.records.filter(
        ({blockAssignmentDoc: {content}}) =>
          content.assignedBlockCount < content.blockCount);
    }
    //  3. Return any fully-assigned cache records.
    return fullyAssigned;
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

  async _getIndexAssignmentDoc({
    blockAssignmentDocId, blockIndex, slSequence
  }) {
    const {edvClient} = this;

    // try to find existing index assignment doc
    const equals = {
      'meta.blockAssignmentDocId': blockAssignmentDocId,
      'meta.blockIndex': blockIndex
    };

    // find existing doc
    const {documents} = await edvClient.find({equals, limit: 1});
    if(documents.length > 0) {
      const [indexAssignmentDoc] = documents;
      return {indexAssignmentDoc};
    }

    // insert new doc, and if duplicate or conflict errors arise, throw
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
  }

  // read BAD contents referenced from LM doc item into a cache record
  async _readBlockAssignmentDoc({item}) {
    const {edvClient, statusListConfig} = this;

    // executes step 1.1 of `populate()`
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
        await _initBlockAssignmentDoc({
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

    // executes step 1.2 of `populate()`
    const cacheRecord = {blockAssignmentDoc, item};
    await this._syncCacheRecord(cacheRecord);
    return cacheRecord;
  }

  // ensure cache record BAD contents are in sync with LM doc item
  async _syncCacheRecord(cacheRecord) {
    // 1.2. If any BAD has an SL sequence number that is behind an LMD item,
    //   CW update it. If conflict, read the BAD.
    if(cacheRecord.blockAssignmentDoc.content.slSequence >=
      cacheRecord.item.slSequence) {
      return cacheRecord;
    }

    try {
      // reset block assignment doc
      await this.resetBlockAssignmentDoc({record: cacheRecord});
    } catch(e) {
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
      // get refreshed record
      cacheRecord.blockAssignmentDoc = await this.edvClient.get({
        id: cacheRecord.blockAssignmentDoc.id
      });
      // set out-of-sync flag if sequence does not match
      if(cacheRecord.blockAssignmentDoc.content.slSequence !==
        cacheRecord.item.slSequence) {
        this._outOfSync = true;
      }
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

async function _initBlockAssignmentDoc({
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

/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import assert from 'assert-plus';
import {Bitstring} from '@digitalbazaar/bitstring';
import {generateLocalId} from './helpers.js';
import {IndexAllocationCache} from './IndexAllocationCache.js';

const {util: {BedrockError}} = bedrock;

/* Notes: The following notes explain the scaling design for assigning
   status list (SL) indexes to VCs in a parallel fashion. This design
   enables multiple "workers" to assign SL indexes and issue VCs concurrently.

1. A list management document (LMD) tracks index allocation state for one or
   more status lists and is identified by the `indexAllocator` value in a
   `statusListConfig`. Index allocation is tracked using blocks of indexes
   of the one or more status lists. The state tracks two sets of block
   assignment documents (BADs) to assist with assigning indexes: an "active"
   set and an "inactive" set. The rationale for having two sets is to allow
   the system to scale up or down based on demand to assign SL indexes,
   to pool and reuse of documents in the backing database, and to enable
   certain non-atomic operations to be continuable, should they fail before
   completing. Each set item is a 3-tuple, a block assignment document (BAD)
   ID, status list metadata that is exposed in VCs, and an SL sequence number
   that is kept private and used to resolve conflicts. Each SL is only ever
   paired with a single BAD, and SL sequence numbers monotonically increase.
2. An "active" BAD enables workers to find an index assignment document (IAD)
   to use to find unused SL indexes to assign to VCs. Once all of the indexes
   for the SLs associated with a BAD are assigned, its active set item is moved
   into the "inactive" set to be reused later if demand requires it.
3. A BAD expresses the current sequence number and an index block size for
   the SLs it is associated with. It also includes an encoded bitstring
   indicating which blocks of indexes have been fully assigned (note: a single
   BAD can be used to facilitate index assignment for VCs that use multiple
   status lists at once (e.g., to track multiple different status purposes)
   because the same index is used in each different list). Whenever the
   last index in a block for one or more related SLs is assigned, the BAD's
   encoded bitstring is updated. If the SL sequence number expressed is behind
   the value in the LMD, then the BAD has been recycled and its bitstring needs
   to be reset. If it is ahead of it, then read LMD content is stale and the
   worker that read it should restart whatever operation it was performing.
4. Database (EDV) unique indexes are used to create/find an IAD for each block
   and BAD pairing. An IAD has an SL sequence number in it that will either
   match the value associated with the BAD or be one less than it, indicating
   that the BAD has been recycled for use and the IAD is ready to be recycled
   as well. If the SL sequence number is ever ahead of the value from the LMD,
   then the worker that read the LMD should restart whatever operation it is
   performing as it is behind other workers. The IAD gets updated every time an
   index is assigned (i.e., whenever a VC referencing the related SL(s) is
   issued); it expresses the latest assigned index and the indexes must be
   assigned in order.
5. As mentioned above, several non-atomic but continuable operations are
   required to implement assigning indexes and issuing VCs. A key primitive
   in enabling continuable operations is a conflictable write (CW). This is
   a write to a database (EDV) where, if a document write fails due to a
   conflict in sequence number, the worker can continue its job by assuming
   another worker completed a functionally equivalent write.

Algorithms:

Note: All of the following algorithms are designed such that they don't need
atomicity, but that they are instead safely "continuable" from any point of
failure. The system continues to make progress even if a single worker
fails, as long as that worker does not create corrupt state (i.e., the
algorithms are implemented correctly). The algorithms do not enable recovery
from corrupt state (misimplementation).

main: The process for issuing a VC with an assigned an index.

0. The worker sets up an in-memory set of list shards (LS), where LS includes
  status list metadata, SL sequence number, BAD, and IAD.
1. Create a CredentialStatusWriter instance `writer`.
2. While a VC has not been successfully written to the database (EDV):
  2.1. Call writer.write(VC).
  2.2. Sign the VC.
  2.3. Attempt to insert the VC in to the database (EDV).
    2.3.1. Note: The database must have a unique index on credential status ID
      (where the ID includes the list identifier and list index), even is that
      credential status ID is not present in a VC, it needs to be present in
      metadata about that VC (the latter is implemented here to enable VCs
      to omit this ID).
  2.4. If a duplicate error occurs, first make sure it is a duplicate error
    due to credential status ID, and if so, loop, otherwise throw.
2. VC has been successfully issued, return it immediately, the receiver of
  the VC response does not need to wait for the following steps to finish.
3. Call writer.finish().
4. Return.

getShard(): Gets a list shard needed to issue a VC. This will be called by
  `writer.write()`.

1. While no LMD exists:
  1.1. CW create the LMD.
  1.2. If conflict, loop to 1.1.
2. Store the LMD in the instance.
3. While true:
  3.1. Call this._readActiveBlockAssignmentDocs().
  3.2. Call this._selectShard() and if result is not `null`, return it.
  3.3. Read LMD and loop to 3.

this._readActiveBlockAssignmentDocs(): Reads all active BADs to enable
  choosing an IAD.

1. While index allocation active cache is not set:
  1.1. Read all active BADs into an index allocation cache, `cache`.
  1.2. If cache is out of sync, read the LMD and loop to 1.
  1.3. Call _tryAddCapacity(cache, target=1).
  1.4. If cache is out of sync, read the LMD and loop to 1.
  1.5. If "active" set is empty, throw insufficient capacity error.
  1.6. Set `cache` as the active cache.

this._selectShard(): Select an IAD to use for assigning indexes:

Note: See `IndexAllocationCache.js`.

1. Return the result of calling `activeCache.selectShard()`.
2. If conflict then another worker has chosen the same IAD:
  2.1. Track failed attempt to choose an IAD due to conflict.
  2.2. Call this._preferNewList(conflicts):
  2.3. If result is false, return `null`. Note: A future
     optimization might be to loop again and make a *different* choice,
     but the code must ensure there are more choices to be made.
  2.4. Otherwise, call _tryAddCapacity(activeCache, target=BADs+1), clear
     tracked failed attempts, read LMD, and then return `null`. Note: A future
     optimization might check to see if capacity was added and update BADs
     accordingly without having to return `null`.

this._preferNewList(conflicts):

1. If conflicts > 1 (50/50 chance of conflict is acceptable, but no more) and
   all active BADs have 50% or more of their blocks assigned, return true,
   otherwise return false.

this._tryAddCapacity(cache, target): Try to add another active BAD if necessary
  (from "inactive" set or a new one):

1. Rotate any active BADs with fully assigned blocks of indexes into the
   "inactive" set.
2. Set `add` to `true` if LMD "active" set size < target and < the
   configured max "active" set size and more status lists can be created.
3. If no rotation occurred and `add` is `false`, return `false` as no
   capacity can be added and the LMD does not need updating.
4. If `add` is true:
  4.1 Create the next set of status lists.
  4.2. Set `slSequence` to the highest SL sequence number amongst
     active+inactive BADs plus 1, to force the BAD that becomes
     associated with the next active item to be auto-reset before reuse.
  4.3. If a rotation occurred, set `toUpdate` to the first rotated
     record, add it to the `cache`, and set the next active item as the
     record's item and remove it from the "inactive" set.
  4.4. Otherwise, if no inactive BADs exist, create a new item with a
     new BAD ID, otherwise, remove the first inactive item for
     modification and mark `cache` as out-of-sync.
  4.5. Set the new active item's status lists and SL sequence number and add it
     to the "active" set.
5. Initialize `added` to `false`.
6. Update LMD, setting `added` to `add` on success and marking
  `cache` as out-of-sync on conflict.
7. If `toUpdate` is set, reset its BAD, marking `cache` as out-of-sync
   on conflict.
8. Return `added` to indicate if capacity was added.

Other notes:

1. Multiple BADs may be created over time to account for demand provided that
   more status lists are permitted to be created. A new BAD should only be
   created when there are more workers actively assigning indexes than there
   are available blocks to assign from and when the existing lists are at
   least half full. This condition is detected when too many conflicts arise
   between different workers that are trying to write to IADs. Note that when
   workers are choosing IADs to assign from, they must make their choice across
   the entire range of unassigned blocks, not just the range of active BADs.
   There is no guarantee that indexes will be assigned evenly across all BADs
   and, in general, newly active BADs should have more available blocks than
   BADs that have been active for a while.
2. We also do not want to allow an unbounded number of concurrent BADs
   to be created (could crash the system, harm its performance, there are
   storage limits, etc.). Furthermore, it is important to be able to reduce
   the number of concurrent BADs if demand cannot keep up with them. If too
   many concurrent BADs are created, then as their respective SLs have all of
   their indexes assigned, these BADs will get reset to refer to new SLs. If
   these BADs are not removed from active use, then it could result in SLs
   with very few to zero assigned indexes. This poses a privacy problem which
   this entire status checking scheme was designed to prevent, i.e., as VCs are
   issued, they should be tightly grouped together using a few SLs as
   possible. Spreading index assignment across many mostly empty SLs defeats
   this goal. Therefore, BADs must scale back as appropriate. Removing them
   cleanly from the LMD, however, has an atomicity problem: they cannot both
   be removed from the LMD and deleted in a single update. So instead of
   deleting BADs, the LMD tracks two sets, one for "active" BADs and one for
   "inactive" BADs.
3. Once a BAD refers to SLs that have had all indexes assigned, its ID is moved
   from the "active" set to the "inactive" set. When the "active" set needs to
   grow, an "inactive" BAD is selected, its contents are reset to refer to
   new SLs (if they can be created), and it is moved to the "active" set. This
   approach prevents the proliferation of extra documents in the storage
   database.
4. The goal of BADs and IADs is to enable workers to issue many VCs
   concurrently. In order to do this and be able to track assigned indexes
   and recover from any crashed operations, it means that there must be at
   least one IAD for every concurrently issuable VC.
*/
export class ListManager {
  constructor({statusListConfig, documentLoader, edvClient, listSource} = {}) {
    assert.object(statusListConfig, 'statusListConfig');
    assert.func(documentLoader, 'documentLoader');
    assert.object(edvClient, 'edvClient');
    assert.object(listSource, 'listSource');
    this.statusListConfig = statusListConfig;
    this.documentLoader = documentLoader;
    this.edvClient = edvClient;
    this.listSource = listSource;
    this.lmDoc = null;
    this.activeCache = null;
    this.conflicts = 0;
  }

  async getShard() {
    this.activeCache = null;
    this.conflicts = 0;

    // initialize edv client, etc.
    await this._init();

    // 1. While no LMD exists:
    //   1.1. CW create the LMD.
    //   1.2. If conflict, loop to 1.1.
    // 2. Store LMD in the instance.
    await this._getListManagementDoc();

    // 3. While true:
    while(true) {
      // 3.1. Call _readActiveBlockAssignmentDocs().
      await this._readActiveBlockAssignmentDocs();
      // 3.2. Call _selectShard() and if result is not `null`, return it.
      const listShard = await this._selectShard();
      if(listShard) {
        return listShard;
      }
      // 3.3. Read LMD and loop to 3.
      this.lmDoc = await this.edvClient.get({id: this.lmDoc.id});
    }
  }

  async _readActiveBlockAssignmentDocs() {
    const {edvClient, statusListConfig} = this;

    // 1. While index allocation active cache is not set:
    this.activeCache = null;
    while(!this.activeCache) {
      // 1.1. Read all active BADs into an index allocation cache, `cache`.
      const {blockAssignment} = this.lmDoc.content;
      const cache = new IndexAllocationCache({statusListConfig, edvClient});
      await cache.populate({items: blockAssignment.active});

      // 1.2. If cache is out of sync, read the LMD and loop to 1.
      if(cache.isOutOfSync()) {
        // FIXME: add a test to ensure this runs
        this.lmDoc = await edvClient.get({id: this.lmDoc.id});
        continue;
      }

      // 1.3. Call _tryAddCapacity(cache, target=1).
      console.log('_tryAddCapacity 1');
      await this._tryAddCapacity({cache, target: 1});

      // 1.4. If cache is out of sync, read the LMD and loop to 1.
      if(cache.isOutOfSync()) {
        this.lmDoc = await edvClient.get({id: this.lmDoc.id});
        continue;
      }

      // 1.5. If "active" set is empty, throw insufficient capacity error.
      if(blockAssignment.active.length === 0) {
        throw new BedrockError(
          'Insufficient capacity; maximum configured list count ' +
          `(${statusListConfig.options.listCount}) reached.`, {
            name: 'QuotaExceededError',
            details: {
              httpStatusCode: 400,
              public: true
            }
          });
      }

      // 1.6. Set `cache` as the active cache.
      this.activeCache = cache;
    }
  }

  async _selectShard() {
    const {activeCache, edvClient} = this;

    try {
      // 1. Return the result of calling `activeCache.selectShard()`.
      const shard = await activeCache.selectShard();
      return shard;
    } catch(e) {
      if(e.name !== 'InvalidStateError' && e.name !== 'DuplicateError') {
        throw e;
      }
      // 2. If conflict then another worker has chosen the same IAD:
      // 2.1. Track failed attempt to choose an IAD due to conflict.
      this.conflicts++;
      // 2.2. Call this._preferNewList(conflicts):
      if(!this._preferNewList()) {
        // 2.3. If result is false, return `null`. Note: A future
        //   optimization might be to loop again and make a *different* choice,
        //   but the code must ensure there are more choices to be made.
        return null;
      }
      // 2.4. Otherwise, call _tryAddCapacity(activeCache, target=BADs+1),
      //   clear tracked failed attempts, read LMD, and then return `null`.
      //   Note: A future optimization might check to see if capacity was added
      //   and update BADs accordingly without having to return `null`.
      console.log('_tryAddCapacity 2');
      await this._tryAddCapacity({
        cache: activeCache,
        target: activeCache.records.length + 1
      });
      this.conflicts = 0;
      this.lmDoc = await edvClient.get({id: this.lmDoc.id});
      return null;
    }
  }

  async _tryAddCapacity({cache, target}) {
    /* Note: A max "active" set size limit of 4, when status list sizes are 16k
    (131072 indexes) and block sizes are 32, means there are 4096 blocks
    (131072 / 32 = 4096) to choose from to perform index assignment per
    "active" item (4). This is 4096 * 4 = 16384 total, so VC issuance
    concurrency without collision is ~sqrt(16384) = 128.

    When a collision happens, another selection can still be made, so there is
    still more concurrency, but it takes more work. On average, every 128
    attempts to find a block to assign indexes from will result in a collision
    that requires additional work to select a different block, but 16384 total
    blocks could actually be theoretrically serviced concurrently, enabling a
    maximum of 16384 VCs to be issued concurrently.

    While setting the max "active" set size limit higher would allow more
    concurrency, it would also reduce the compactness of index assignment which
    can harm group privacy. The total population (number of VCs being issued
    over a reasonable period of time) must be divided by the max "active" set
    size limit to get the group size, because each status list is associated
    with just one "active" set item. For example, the concurrent issuance of
    100k VCs would be spread across 4 different status lists, yielding group
    sizes of only 25k. */
    // TODO: read max active list limit from status list config
    const maxActiveListSize = 4;

    // 1. Rotate any active BADs with fully assigned blocks of indexes
    //   into the "inactive" set.
    const {blockAssignment} = this.lmDoc.content;
    const rotated = cache.rotate({blockAssignment});

    // 2. Set `add` to `true` if LMD "active" set size < target and < the
    //   configured max "active" set size and more status lists can be created.
    const add = (blockAssignment.active.length < target &&
      blockAssignment.active.length < maxActiveListSize &&
      this._canCreateNextStatusLists());

    // 3. If no rotation occurred and `add` is `false`, return `false` as no
    //   capacity can be added and the LMD does not need updating.
    if(rotated.length === 0 && !add) {
      return false;
    }

    // 4. If `add` is true:
    let toUpdate;
    let newActiveItem;
    if(add) {
      // 4.1 Create the next set of status lists.
      const {nextStatusLists} = this.lmDoc.content;
      await this._createNextStatusLists();

      // 4.2. Set `slSequence` to the highest SL sequence number amongst
      //   active+inactive BADs plus 1, to force the BAD that becomes
      //   associated with the next active item to be auto-reset before reuse.
      const slSequence = _maxSlSequence(blockAssignment) + 1;

      // 4.3. If a rotation occurred, set `toUpdate` to the first rotated
      //   record, add it to the `cache`, and set the next active item as the
      //   record's item and remove it from the "inactive" set.
      if(rotated.length > 0) {
        toUpdate = rotated[0];
        cache.records.push(toUpdate);
        newActiveItem = toUpdate.item;
        blockAssignment.inactive = blockAssignment.inactive.filter(
          item => item !== toUpdate.item);
      } else {
        // 4.4. Otherwise, if no inactive BADs exist, create a new item with a
        //   new BAD ID, otherwise, remove the first inactive item for
        //   modification and mark `cache` as out-of-sync.
        newActiveItem = blockAssignment.inactive.shift();
        if(!newActiveItem) {
          newActiveItem = {
            blockAssignmentEdvDocId: await this.edvClient.generateId()
          };
        }
        cache.outOfSync = true;
      }

      // 4.5. Set the new active item's status lists and SL sequence number and
      //   add it to the "active" set.
      newActiveItem.statusLists = nextStatusLists;
      newActiveItem.slSequence = slSequence;
      blockAssignment.active.push(newActiveItem);
    }

    // 5. Initialize `added` to `false`.
    let added = false;
    try {
      // 6. Update LMD, setting `added` to `add` on success and marking
      //   `cache` as out-of-sync on conflict.
      this.lmDoc = await this.edvClient.update({doc: this.lmDoc});
      added = add;

      // 7. If `toUpdate` is set, reset its BAD, marking `cache` as out-of-sync
      //   on conflict.
      if(toUpdate) {
        /* Note: We reset the newly active BAD and update the cache record
        here so we don't have to repopulate the whole cache again in `step 1.2`.
        If we just marked `cache` out-of-sync and skipped this update instead,
        it would work properly, but would be slower because the active items
        all have to be reread when that is not required if the update to
        `toUpdate` succeeds w/o conflict. */
        // FIXME: add two tests, one to skip this update and another that will
        // cause a conflict to trigger the `catch`
        await cache.resetBlockAssignmentDoc({record: toUpdate});
      }
    } catch(e) {
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
      cache.outOfSync = true;
    }

    // 8. Return `added` to indicate if capacity was added.
    return added;
  }

  _preferNewList() {
    // 1. If conflicts > 1 (50/50 chance of conflict is acceptable, but no more)
    //   and all active BADs have 50% or more of their blocks assigned, return
    //   true, otherwise return false.
    const {conflicts, activeCache} = this;
    if(conflicts < 2) {
      return false;
    }
    return activeCache.records.every(({blockAssignmentDoc: {content}}) =>
      (content.assignedBlockCount / content.blockCount) >= 0.5);
  }

  _canCreateNextStatusLists() {
    // return whether there are any next status lists
    const {nextStatusLists} = this.lmDoc.content;
    return nextStatusLists.length > 0;
  }

  // creates the next SLs on demand and updates the current LM doc content
  // (without writing to the database) with a new set of SLC IDs for next time
  async _createNextStatusLists() {
    // get next status lists metadata
    const {nextStatusLists, listAssignment} = this.lmDoc.content;
    console.log('nextStatusLists', nextStatusLists);

    // create each status list in parallel
    await Promise.all(nextStatusLists.map(
      e => this.listSource.createStatusList(e)));

    // mark list assigned if applicable
    if(listAssignment) {
      // note: all `nextStatusLists` use the same `listIndex`
      const {listIndex} = nextStatusLists[0];
      const {assignedLists} = listAssignment;
      const buffer = await Bitstring.decodeBits({encoded: assignedLists});
      const bs = new Bitstring({buffer});
      bs.set(listIndex, true);
      listAssignment.assignedLists = await bs.encodeBits();
      listAssignment.assignedListCount++;
    }

    // create next status lists metadata
    this.lmDoc.content.nextStatusLists = await this._createStatusListMeta({
      listAssignment
    });
  }

  async _createStatusListMeta({listAssignment} = {}) {
    // generate new SLC IDs for each ID and set them in LM doc;
    // determine how many SLC IDs to generate how they should look (total list
    // count is limited, aka, "terse", or not)
    const {baseUrl, statusPurpose, options} = this.statusListConfig;
    const purposes = Array.isArray(statusPurpose) ?
      statusPurpose : [statusPurpose];
    const length = options.blockCount * options.blockSize;
    if(options.listCount === undefined) {
      // not overall list limit; generate random local ID for each SLC
      return Promise.all(purposes.map(async statusPurpose => {
        return {
          id: `${baseUrl}/${await generateLocalId()}`,
          statusPurpose,
          length
        };
      }));
    }

    /* Note: In the case of a limited list count, there is some total amount of
    "list index space" for which N-many lists (bounded) can be created (e.g.,
    32768 lists with a list size of 131072 is 2^32 total list index space). The
    next list-sized chunk of total "list index space" is selected at random
    and expressed as a `listIndex`. This `listIndex` is used to compute the
    starting offset for the associated list (based the total list index space)
    and this value is used as a part of the new SLC ID(s).

    Which lists have been assigned is stored in a bitstring representing all
    N-many lists in the LDM. */

    // if all lists are already assigned, return `[]` for next SLC IDs
    if(listAssignment.assignedListCount === options.listCount) {
      return [];
    }
    // choose next list at random from available lists
    const {listIndex} = await _chooseRandom({listAssignment});
    return purposes.map(statusPurpose => {
      const encodedStatusPurpose = encodeURIComponent(statusPurpose);
      return {
        id: `${baseUrl}/${encodedStatusPurpose}/${listIndex}`,
        statusPurpose,
        length,
        listIndex
      };
    });
  }

  async _getListManagementDoc() {
    const {edvClient} = this;

    // try to find existing LMD using `indexAllocator` as ID
    const {statusListConfig: {indexAllocator, options}} = this;
    const equals = {'content.id': indexAllocator};
    while(true) {
      // find existing LMD
      const {documents} = await edvClient.find({equals, limit: 1});
      if(documents.length > 0) {
        this.lmDoc = documents[0];
        return;
      }

      // track list assignment when using a limited total list count
      let listAssignment;
      if(options.listCount !== undefined) {
        const bs = new Bitstring({length: options.listCount});
        listAssignment = {
          assignedLists: await bs.encodeBits(),
          assignedListCount: 0,
          listCount: options.listCount
        };
      }

      // no LMD found, upsert it
      const type = 'StatusListManagementDocument';
      const lmDoc = {
        id: await edvClient.generateId(),
        content: {
          id: indexAllocator,
          type,
          // each element has an `id` and other meta data for the next status
          // lists to be created
          nextStatusLists: await this._createStatusListMeta({listAssignment}),
          blockAssignment: {
            active: [],
            inactive: []
          }
        },
        meta: {type}
      };
      if(listAssignment) {
        lmDoc.content.listAssignment = listAssignment;
      }
      try {
        this.lmDoc = await edvClient.update({doc: lmDoc});
        return;
      } catch(e) {
        // only ignore duplicate error, throw otherwise
        if(e.name !== 'DuplicateError') {
          throw e;
        }
      }
    }
  }

  async _init() {
    this.edvClient.ensureIndex({
      attribute: ['meta.blockAssignmentDocId', 'meta.blockIndex'],
      unique: true
    });
  }
}

async function _chooseRandom({listAssignment}) {
  const {assignedLists, assignedListCount, listCount} = listAssignment;

  // FIXME: reuse some code from `IndexAllocationCache.js` here

  // choose one of the unassigned lists
  let choice = Math.floor(Math.random() * assignedListCount);
  // map the choice to a specific list index
  // note: see `IndexAllocationCache.js` `_chooseRandom()` helper for a
  // description of a similar mapping algorithm as is used here
  const buffer = await Bitstring.decodeBits({encoded: assignedLists});
  const bs = new Bitstring({buffer});
  for(let listIndex = 0; listIndex < listCount; ++listIndex) {
    // if list is unassigned...
    if(!bs.get(listIndex)) {
      if(choice === 0) {
        // `choice` found
        return {listIndex};
      }
      // this is not the unassigned list we're looking for
      choice--;
    }
  }
}

function _maxSlSequence(blockAssignment) {
  return Math.max(
    _maxSlSequenceFromItems(blockAssignment.active),
    _maxSlSequenceFromItems(blockAssignment.inactive));
}

function _maxSlSequenceFromItems(items) {
  return items.reduce((max, {slSequence}) => Math.max(max, slSequence), 0);
}

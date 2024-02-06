/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import {Bitstring} from '@digitalbazaar/bitstring';
import {generateLocalId} from './helpers.js';
import {ListSource} from './ListSource.js';
import {v4 as uuid} from 'uuid';

/* Notes: The following notes explain the scaling design for assigning
   status list (SL) indexes to VCs in a parallel fashion. This design
   enables multiple "workers" to assign SL indexes and issue VCs concurrently.

1. The list management document (LMD) keeps two lists: an "active" list and
   an "inactive" list. The rationale for having two lists is to allow the
   system to scale up or down based on demand to assign SL indexes and to
   enable certain non-atomic operations to be continuable, should they fail
   before completing. Each list item is a 3-tuple, a block assignment document
   (BAD) ID, an SL ID that is exposed in VCs, and an SL list sequence number
   that is kept private. Each SL (including its ID and sequence number) is only
   ever paired with a single BAD, and SL list sequence numbers monotonically
   increase.
2. An "active" BAD enables workers to find an index assignment document (IAD)
   to use to find unused SL indexes to assign to VCs. Once all of the indexes
   for an SL associated with a BAD are assigned, its active list item is moved
   into the "inactive" list to be reused later if demand requires it.
3. A BAD expresses the current sequence number and an index block size for
   the SL it is associated with. It also includes an encoded bitstring
   indicating which blocks of indexes have been fully assigned. Whenever the
   last index in a block for an SL is assigned, the BAD's encoded bitstring
   is updated. If the SL sequence number expressed is behind the value in the
   LMD, then the BAD has been recycled and its bitstring needs to be reset. If
   it is ahead of it, then read LMD content is stale and the worker that read
   it should restart whatever operation it was performing.
4. Database (EDV) unique indexes are used to create/find an IAD for each block
   and BAD pairing. An IAD has an SL sequence number in it that will either
   match the value associated with the BAD or be one less than it, indicating
   that the BAD has been recycled for use and the IAD is ready to be recycled
   as well. If the SL sequence number is ever ahead of the value from the LMD,
   then the worker that read the LMD should restart whatever operation it is
   performing as it is behind other workers. The IAD gets updated every time an
   index is assigned (i.e., whenever a VC referencing the related SL is
   issued); it expresses the latest assigned index and it indexes must be
   assigned in order.
5. As mentioned above, several non-atomic but continuable operations are
   required to implement assigning indexes and issuing VCs. A key primitive
   in enabling continuable operations is a conflictable write (CW). This
   a write to a database (EDV) where if a document write fails due to a
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

getShard(): Gets a list shard needed to issue a VC. This will be called by
  `writer.write()`.

1. While no LMD exists:
  1.1. CW create the LMD.
  1.2. If conflict, loop to 1.1.
2. Store the LMD in the instance.
3. While true:
  3.1. Call this._readActiveBlockAssignmentDocs(LMD).
  3.2. Call this._selectShard(LMD, BADs) and if result is not `null`,
    return it.

this._readActiveBlockAssignmentDocs(LMD): Reads all active BADs to enable
  choosing an IAD.

1. While active BADs not read:
  1.1. Call _tryAddCapacity(LMD, target=1).
  1.2. Read all active BADs.
    1.2.1. If any BAD does not exist, CW create it.
    1.2.2. If any BAD has an SL sequence number that is behind the LMD,
      CW update it. If conflict, read the BAD.
    1.2.3. If any BAD has an SL sequence number that is ahead of the
      LMD active list item, read the LMD and loop to 1.
  1.3. If any BADs have fully assigned blocks of indexes:
    1.3.1. Move BAD IDs to the "inactive" list; if all BADs are fully assigned,
      choose one to leave as active and update its SL ID and SL sequence number.
    1.3.2. CW update LMD.
    1.3.3. If conflict, read LMD and loop to 1.
    1.3.4. CW update active BAD, if one was updated.
    1.3.5. If conflict, read active BAD. If BAD SL sequence does not match
      LMD active list item, read LMD and loop to 1.
  1.4. Store read BADs in the instance.

this._selectShard(LMD, activeBADs): Select an IAD to use for assigning
  indexes:

1. Select an IAD at random from the BAD blocks with unassigned indexes:
  1.1. Get total number of unassigned blocks and choose randomly.
  1.2. Use choice to find chosen IAD and block index.
2. CW create the IAD if it does not exist or if IAD's SL sequence number
  is behind the one associated with the BAD, CW update the IAD to reset it.
  2.1. If conflict then another worker has chosen the same IAD:
    2.1.1. Track failed attempt to choose an IAD due to conflict.
    2.1.2. Call this._needCapacity(conflicts, BADs):
      2.1.2.1. If result is false, return `null`. Note: A future
        optimization might be to loop again and make a *different* choice,
        but the code must ensure there are more choices to be made.
      2.1.2.2. Otherwise, call _tryAddCapacity(LMD, target=BADs+1), clear
        tracked failed attempts, and then return `null`. Note: A future
        optimization might check to see if capacity was added and update BADs
        accordingly without having to return `null`.
3. If the IAD's SL sequence number is ahead, return `null`.
4. If the IAD's indexes have all been assigned:
  4.1. CW update the BAD to indicate the IAD block has been assigned.
  4.2. If conflict, ignore.
  4.3. Return `null`. Note: A future optimization might be to loop
    again and make a *different* choice, but the code must ensure
    there are more choices to be made.
5. Return SL ID, SL sequence number, BAD, and IAD.

this._needCapacity(conflicts, activeBADs):

1. If conflicts > 1 (50/50 chance of conflict is acceptable, but no more) and
   all active BADs have 50% or more of their blocks assigned, return true,
   otherwise return false.

this._tryAddCapacity(target): Try to add another active BAD if necessary (from
  inactive list or a new one):

1. While LMD active list size < target:
  1.1. Set `need` = target - LMD active list size. Cap `need` by
    min(1, min(need, max configured active list size - LMS active list size))).
  1.2. If `need` === 0, return `false`, capacity not added.
  1.3. Set `sn` to the highest SL sequence number amongst active+inactive BADs.
  1.4. Create the next set of status lists.
  1.5. If no inactive BADs exist, create a new item with a new BAD ID,
    otherwise, remove the first inactive item for modification.
  1.6. Update the new / newly active item, setting the SL ID and SL sequence
    number (using `++sn`).
  1.7. CW update LMD and return `true` if no conflict.
  1.8. If conflict, read the LMD.
2. Return `false`, capacity not added.

Other notes:

1. Multiple BADs may be created over time to account for demand. A new BAD
   should only be created when there are more workers actively assigning
   indexes than there are available blocks to assign from. This condition
   is detected when too many conflicts arise between different workers that
   are trying to write to IADs. Note that when workers are choosing IADs to
   assign from, they must make their choice across the entire range of
   unassigned blocks, not just the range of active BADs. There is no
   guarantee that indexes will be assigned evenly across all BADs and, in
   general, newly active BADs should have more available blocks than BADs
   that have been active for a while.
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
   deleting BADs, the LMD expresses two lists, one for active BADs and one that
   expresses inactive BADs.
3. Once a BAD refers to an SL that has assigned all of its indexes, its ID
   is moved from the active list to the inactive list. When the active list
   needs to grow, an inactive BAD is selected, its contents are reset to refer
   to a new SL, and it is moved to the active list.
4. The goal of BADs and IADs is to enable workers to issue many VCs
   concurrently. In order to do this and be able to track assigned indexes
   and recover from any crashed operations, it means that there must be at
   least one IAD for every concurrently issuable VC.
*/
export class ListManager {
  // FIXME: pass in ListSource API instance
  constructor({
    id, slcsBaseUrl, documentLoader, documentStore,
    issuer, statusListConfig, suite
  } = {}) {
    assert.string(id, 'id');
    assert.string(slcsBaseUrl, 'slcsBaseUrl');
    assert.func(documentLoader, 'documentLoader');
    assert.object(documentStore, 'documentStore');
    assert.object(statusListConfig, 'statusListConfig');
    assert.string(issuer, 'issuer');
    assert.object(suite, 'suite');
    if(!slcsBaseUrl) {
      throw new TypeError('"slcsBaseUrl" must be a non-empty string.');
    }
    if(!issuer) {
      throw new TypeError('"issuer" must be a non-empty string.');
    }
    this.id = id;
    this.slcsBaseUrl = slcsBaseUrl;
    this.documentLoader = documentLoader;
    this.documentStore = documentStore;
    this.issuer = issuer;
    this.statusListConfig = statusListConfig;
    this.suite = suite;
    this.lmDoc = null;
    this.readActiveList = null;
    this.conflicts = 0;

    // FIXME: pass in list source instance
    this.listSource = new ListSource({
      slcsBaseUrl, documentLoader, documentStore,
      issuer, statusListConfig, suite
    });
  }

  async getShard() {
    this.readActiveList = null;
    this.conflicts = 0;

    // initialize edv client, etc.
    await this._init();

    // 1. While no LMD exists:
    //   1.1. CW create the LMD.
    //   1.2. If conflict, loop to 1.1.
    await this._getListManagementDoc();

    // 2. While true:
    while(true) {
      // 2.1. Call _readActiveBlockAssignmentDocs().
      await this._readActiveBlockAssignmentDocs();
      // 2.2. Call _selectShard() and if result is not `null`, return it.
      const listShard = await this._selectShard();
      // 2.3. If `listShard` is not `null`, return it.
      if(listShard) {
        return listShard;
      }
    }
  }

  async _readActiveBlockAssignmentDocs() {
    // get `edvClient` directly; do not use cache in `documentStore` to ensure
    // latest docs are used
    const {documentStore: {edvClient}, statusListConfig} = this;

    // 1. While active BADs not read:
    this.readActiveList = null;
    while(!this.readActiveList) {
      // 1.1. Call _tryAddCapacity(LMD, target=1).
      await this._tryAddCapacity({target: 1});
      // 1.2. Read all active BADs.
      const {blockAssignment: {active}} = this.lmDoc.content;
      // 1.2.1. If any BAD does not exist, CW create it.
      let readItems = await Promise.all(active.map(
        item => this._readBlockAssignmentDoc({item})));
      // 1.2.2. If any BAD has an SL sequence number that is behind the LMD,
      //   CW update it. If conflict, read the BAD.
      await Promise.all(readItems.map(async x => {
        if(x.blockAssignmentDoc.content.slSequence < x.item.slSequence) {
          try {
            // reset block assignment doc
            const {content} = x.blockAssignmentDoc;
            await _resetBlockAssignmentDoc({
              content, slSequence: x.item.slSequence, statusListConfig
            });
            x.blockAssignmentDoc = await edvClient.update({
              doc: x.blockAssignmentDoc
            });
          } catch(e) {
            if(e.name !== 'InvalidStateError') {
              throw e;
            }
            x.blockAssignmentDoc = await edvClient.get({
              id: x.blockAssignmentDoc.id
            });
          }
        }
      }));
      // 1.2.3. If any BAD has an SL sequence number that is ahead of the
      //   LMD active list item, read the LMD and loop to 1.
      if(readItems.some(({blockAssignmentDoc: {content}, item}) =>
        content.slSequence > item.slSequence)) {
        this.lmDoc = await edvClient.get({id: this.lmDoc.id});
        continue;
      }

      // 1.3. If any BADs have fully assigned blocks of indexes:
      const fullyAssigned = readItems.filter(
        ({blockAssignmentDoc: {content}}) =>
          content.assignedBlockCount === content.blockCount);
      if(fullyAssigned.length > 0) {
        // 1.3.1. Move BAD IDs to the "inactive" list; if all BADs are fully
        //   assigned, choose one to leave as active and update its SL ID and
        //   SL sequence number.
        const {blockAssignment} = this.lmDoc.content;
        const items = fullyAssigned.map(({item}) => item);
        blockAssignment.inactive.push(...items);
        blockAssignment.active = blockAssignment.active.filter(
          // remove fully assigned from active list
          x => !items.includes(x));
        let toUpdate;
        if(blockAssignment.active.length > 0) {
          // active items remain, will use those
          readItems = readItems.filter(
            ({blockAssignmentDoc: {content}}) =>
              content.assignedBlockCount < content.blockCount);
        } else {
          // no active items remain, must update an inactive one
          toUpdate = fullyAssigned[0];
          blockAssignment.inactive = blockAssignment.inactive.filter(
            x => x !== toUpdate.item);
          blockAssignment.active = [toUpdate.item];
          readItems = [toUpdate];
          // create next SL lists
          const {nextSlcIds: slcIds} = this.lmDoc.content;
          await this._createNextStatusLists();
          // update LMD active list item
          // FIXME: determine how SLC IDs will be stored
          // toUpdate.item.slcIds = slcIds;
          toUpdate.item.statusListCredential = slcIds[0].id;
          // use maximum `slSequence` from all fully assigned items, plus 1
          toUpdate.item.slSequence = items.reduce(
            (max, {slSequence}) => Math.max(max, slSequence), 0) + 1;
          // reset BAD content automatically so it doesn't need to be
          // re-read again and updated in 1.2.2 in the optimistic case
          // reset block assignment doc
          const {content} = toUpdate.blockAssignmentDoc;
          await _resetBlockAssignmentDoc({
            content, slSequence: toUpdate.item.slSequence, statusListConfig
          });
        }
        // 1.3.2. CW update LMD.
        try {
          this.lmDoc = await edvClient.update({doc: this.lmDoc});
        } catch(e) {
          if(e.name !== 'InvalidStateError') {
            throw e;
          }
          // 1.3.3. If conflict, read LMD and loop to 1.
          this.lmDoc = await edvClient.get({id: this.lmDoc.id});
          continue;
        }
        // 1.3.4. CW update active BAD, if one was updated.
        if(toUpdate) {
          try {
            toUpdate.blockAssignmentDoc = await edvClient.update(
              {doc: toUpdate.blockAssignmentDoc});
          } catch(e) {
            if(e.name !== 'InvalidStateError') {
              throw e;
            }
            // 1.3.5. If conflict, read active BAD. If BAD SL sequence does not
            //  match LMD active list item, read LMD and loop to 1.
            toUpdate.blockAssignmentDoc = await edvClient.get(
              {id: toUpdate.blockAssignmentDoc.id});
            if(toUpdate.blockAssignmentDoc.content.slSequence !==
              toUpdate.item.slSequence) {
              this.lmDoc = await edvClient.get({id: this.lmDoc.id});
              continue;
            }
          }
        }
      }
      // 1.4. Store read BADs in the instance.
      this.readActiveList = readItems;
    }
  }

  async _selectShard() {
    // get `edvClient` directly; do not use cache in `documentStore` to ensure
    // latest docs are used
    const {documentStore: {edvClient}} = this;

    // 1. Select an IAD at random from the BAD blocks with unassigned indexes:
    //   1.1. Get total number of unassigned blocks and choose randomly.
    //   1.2. Use choice to find chosen IAD and block index.
    const {readActiveList} = this;
    const choice = await _chooseRandom({readActiveList});

    // 2. CW create the IAD if it does not exist or if IAD's SL sequence number
    //   is behind the one associated with the BAD, CW update the IAD to reset
    //   it.
    const {blockIndex, blockAssignmentDoc} = choice;
    const {content: {slSequence}} = blockAssignmentDoc;
    const blockAssignmentDocId = blockAssignmentDoc.content.id;
    let indexAssignmentDoc;
    try {
      ({indexAssignmentDoc} = await this._getIndexAssignmentDoc(
        {blockAssignmentDocId, blockIndex, slSequence}));
      if(indexAssignmentDoc.content.slSequence < slSequence) {
        // TODO: add a function for resetting an IAD
        indexAssignmentDoc.content.slSequence = slSequence;
        indexAssignmentDoc.content.nextLocalIndex = 0;
        indexAssignmentDoc = await edvClient.update({doc: indexAssignmentDoc});
      }
    } catch(e) {
      if(e.name !== 'InvalidStateError' && e.name !== 'DuplicateError') {
        throw e;
      }
      // 2.1. If conflict then another worker has chosen the same IAD:
      // 2.1.1. Track failed attempt to choose an IAD due to conflict.
      this.conflicts++;
      // 2.1.2. Call this._needCapacity(conflicts, BADs):
      if(!this._needCapacity()) {
        // 2.1.2.2. If result is false, return `null`. Note: A future
        //   optimization might be to loop again and make a *different* choice,
        //   but the code must ensure there are more choices to be made.
        return null;
      }
      // 2.1.2.1. Otherwise, call _tryAddCapacity(LMD, target=BADs+1), clear
      //   tracked failed attempts, and then return `null`. Note: A future
      //   optimization might check to see if capacity was added and update
      //   BADs accordingly without having to return `null`.
      await this._tryAddCapacity({target: readActiveList.length + 1});
      this.conflicts = 0;
      return null;
    }

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

  async _tryAddCapacity({target}) {
    /* Note: A max active list limit of 4 when list sizes are 16k (131072
    indexes) and block sizes are 32, means there are 4096 blocks to choose from
    for each active list (4), which is 16384 total, so concurrency without
    collision is ~sqrt(16384), which is 128.

    When a collision happens, another selection can still be made, so there is
    still more concurrency it just takes more work. On average, every 128
    attempts to find a block to assign indexes from will result in a collision
    that requires additional work to select a different block, but 16384 total
    blocks could actually be theoretrically serviced concurrently, enabling a
    maximum of 16384 VCs to be issued concurrently.

    While setting the max active list limit higher would allow more
    concurrency, it would also reduce the compactness of index assignment which
    can harm group privacy. The total population (number of VCs being issued
    over a reasonable period of time) must be divided by the max active list
    limit to get the group size. For example, a total population of 100k would
    be spread across 4 lists, yielding group sizes of only 25k. */
    // TODO: read max active list limit from config
    const maxActiveListSize = 4;

    // get `edvClient` directly; do not use cache in `documentStore` to ensure
    // latest docs are used
    const {documentStore: {edvClient}} = this;

    // 1. While LMD active list size < target:
    let activeListSize = this.lmDoc.content.blockAssignment.active.length;
    while(activeListSize < target) {
      const {blockAssignment} = this.lmDoc.content;
      // 1.1. Set `need` = target - LMD active list size. Cap `need` by
      // min(1, min(need, max - LMS active list size))).
      const need = Math.min(1, Math.min(
        target - activeListSize,
        // do not allow negative if `maxActiveListSize` has changed
        Math.max(0, maxActiveListSize - activeListSize)));
      // 1.2. If `need` === 0, return `false`, capacity not added.
      if(need === 0) {
        return false;
      }
      // 1.3. Set `sn` to the highest SL sequence number amongst
      //   active+inactive BADs.
      let sn = blockAssignment.active.reduce(
        (max, x) => Math.max(max, x.slSequence), 0);
      sn = blockAssignment.inactive.reduce(
        (max, x) => Math.max(max, x.slSequence), sn);
      // 1.4. Create the next set of status lists.
      const {nextSlcIds: slcIds} = this.lmDoc.content;
      await this._createNextStatusLists();
      // 1.5. If no inactive BADs exist, create a new item with a new BAD ID,
      //   otherwise, remove the first inactive item for modification.
      let newActive = blockAssignment.inactive.shift();
      if(!newActive) {
        newActive = {blockAssignmentEdvDocId: await edvClient.generateId()};
      }
      // FIXME: determine how SLC IDs will be stored
      //newActive.slcIds = slcIds;
      newActive.statusListCredential = slcIds[0].id;
      // note: incrementing `slSequence` will force the related BAD content
      // to be auto-reset in `_readBlockAssignmentDoc()` before use
      newActive.slSequence = ++sn;
      blockAssignment.active.push(newActive);
      // 1.7. CW update LMD.
      try {
        this.lmDoc = await edvClient.update({doc: this.lmDoc});
        // capacity added, return `true`
        return true;
      } catch(e) {
        if(e.name !== 'InvalidStateError') {
          throw e;
        }
        // 1.8. If conflict, read the LMD.
        this.lmDoc = await edvClient.get({id: this.lmDoc.id});
      }
      activeListSize = this.lmDoc.content.blockAssignment.active.length;
    }
    // 2. Return `false`, capacity not added.
    return false;
  }

  _needCapacity() {
    // 1. If conflicts > 1 (50/50 chance of conflict is acceptable, but no more)
    //   and all active BADs have 50% or more of their blocks assigned, return
    //   true, otherwise return false.
    const {conflicts, readActiveList} = this;
    if(conflicts < 2) {
      return false;
    }
    // FIXME: if "terse" mode is used and all blocks are FULLY assigned, then
    // throw an exception
    return readActiveList.every(({blockAssignmentDoc: {content}}) =>
      (content.assignedBlockCount / content.blockCount) >= 0.5);
  }

  // creates the next SLs on demand and updates the current LM doc content
  // (without writing to the database) with a new set of SLC IDs for next time
  async _createNextStatusLists() {
    // get next SLC IDs
    const {nextSlcIds: currentSlcIds} = this.lmDoc.content;

    // create each SLC in parallel
    await Promise.all(currentSlcIds.map(
      e => this.listSource.createStatusList(e)));

    // create next SLC IDs
    this.lmDoc.content.nextSlcIds = await this._createSlcIds();
  }

  async _createSlcIds() {
    // generate new SLC IDs for each ID and set them in LM doc;
    // determine how many SLC IDs to generate how they should look (terse / not)
    const {statusPurpose, terse, options} = this.statusListConfig;
    const purposes = Array.isArray(statusPurpose) ?
      statusPurpose : [statusPurpose];
    const length = options.blockCount * options.blockSize;
    if(terse) {
      // FIXME: in the case of a terse list, the next list-sized block of
      // total index space is selected at random and the starting offset for it
      // stored in the LM doc; the next time a list is needed that value is used
      // for the prefix of the list to be created and a new one is randomly
      // selected again -- which indexes have been used is stored in a bitstring
      // representing all 32768 lists
      // FIXME: `lmDoc.content.usedLists` (name TBD) bitstring must be used
      // externally to choose
      throw new Error('Not implemented.');
      //return [];
    } else {
      // not overall index limit; generate random local ID for each SLC
      return Promise.all(purposes.map(async statusPurpose => {
        return {
          id: `${this.slcsBaseUrl}/${await generateLocalId()}`,
          statusPurpose,
          length
        };
      }));
    }
  }

  async _getListManagementDoc() {
    // get `edvClient` directly; do not use cache in `documentStore` to ensure
    // latest docs are used
    const {documentStore: {edvClient}} = this;

    // try to find existing LMD
    const equals = {'content.id': this.id};
    while(true) {
      const {documents} = await edvClient.find({equals, limit: 1});
      if(documents.length === 0) {
        const type = 'StatusListManagementDocument';
        const lmDoc = {
          id: await edvClient.generateId(),
          content: {
            id: this.id,
            type,
            // each element has an `id` for the SLC, a `statusPurpose`, and
            // the list length
            nextSlcIds: await this._createSlcIds(),
            blockAssignment: {
              active: [],
              inactive: []
            }
          },
          meta: {type}
        };
        try {
          this.lmDoc = await edvClient.update({doc: lmDoc});
          return;
        } catch(e) {
          // only ignore duplicate error, throw otherwise
          if(e.name !== 'DuplicateError') {
            throw e;
          }
        }
      } else {
        this.lmDoc = documents[0];
        return;
      }
    }
  }

  async _readBlockAssignmentDoc({item}) {
    // get `edvClient` directly; do not use cache in `documentStore` to ensure
    // latest docs are used
    const {documentStore: {edvClient}, statusListConfig} = this;
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
    return {blockAssignmentDoc, item};
  }

  async _getIndexAssignmentDoc({
    blockAssignmentDocId, blockIndex, slSequence
  }) {
    // get `edvClient` directly; do not use cache in `documentStore` to ensure
    // latest docs are used
    const {documentStore: {edvClient}} = this;

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

  async _init() {
    const {documentStore: {edvClient}} = this;
    edvClient.ensureIndex({
      attribute: ['meta.blockAssignmentDocId', 'meta.blockIndex'],
      unique: true
    });
  }
}

async function _chooseRandom({readActiveList}) {
  const unassignedBlockCount = readActiveList.reduce((count, x) => {
    const {blockAssignmentDoc: {content}} = x;
    return count + content.blockCount - content.assignedBlockCount;
  }, 0);
  let choice = Math.floor(Math.random() * unassignedBlockCount);
  // choice is based on total unassigned blocks, now must map the choice
  // to an actual block index by mapping it
  let blockIndex = 0;
  // note: `readActiveList` is assumed to never be empty per the design
  for(const x of readActiveList) {
    const {blockAssignmentDoc: {content}} = x;
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
      return {...x, blockIndex};
    }
  }
}

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

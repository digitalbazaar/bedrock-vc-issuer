/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// FIXME: replace `uuid` with bnid
const {util: {uuid}} = require('bedrock');
const {EdvClient} = require('edv-client');
const {
  Bitstring,
  createList,
  createCredential: createRlc
} = require('vc-revocation-list');
const {issue} = require('./helpers');
const rlcs = require('./rlc');

// load config defaults
require('./config');

// FIXME: bikeshed
const LM_DOC_ID = 'urn:vc-issuer:rl2020-lm';

// FIXME: make configurable/option
const BLOCK_COUNT = 1024;
const BLOCK_SIZE = 128;

/* Notes: The following notes explain the scaling design for assigning
   revocation list (RL) indexes to VCs in a parallel fashion. This design
   enables multiple "workers" to assign RL indexes and issue VCs concurrently.

1. The list management (LM) document keeps two lists: an "active" list and
   an "inactive" list. The rationale for having two lists is to allow the
   system to scale up or down based on demand to assign RL indexes and to
   enable certain non-atomic operations to be continuable, should they fail
   before completing. Each list item is a 3-tuple, a block assignment document
   (BAD) ID, an RL ID (part of which is chosen randomly) that is exposed
   in VCs, and an RL list sequence number that is kept private. Each RL
   (including its ID and sequence number) is only ever paired with a single
   BAD, and RL list sequence numbers monotonically increase.
2. An "active" BAD enables workers to find an index assignment document (IAD)
   to use to find unused RL indexes to assign to VCs. Once all of the indexes
   for an RL associated with a BAD are assigned, its active list item is moved
   into the "inactive" list to be reused later if demand requires it.
3. A BAD expresses the current sequence number and an index block size for
   the RL it is associated with. It also includes an encoded bitstring
   indicating which blocks of indexes have been fully assigned. Whenever the
   last index in a block for an RL is assigned, the BAD's encoded bitstring
   is updated. If the RL sequence number expressed is behind the value in the
   LM, then the BAD has been recycled and its bitstring needs to be reset. If
   it is ahead of it, then read LM content is stale and the worker that read
   it should restart whatever operation it was performing.
4. Database (EDV) unique indexes are used to create/find an IAD for each block
   and BAD pairing. An IAD has an RL sequence number in it that will either
   match the value associated with the BAD or be one less than it, indicating
   that the BAD has been recycled for use and the IAD is ready to be recycled
   as well. If the RL sequence number is ever ahead of the value from the LM,
   then the worker that read the LM should restart whatever operation it is
   performing as it is behind other workers. The IAD gets updated every time an
   index is assigned (i.e., whenever a VC referencing the related RL is
   issued); it expresses the latest assigned index and it indexes must be
   assigned in order.
5. As mentioned above, several non-atomic but continuable operations are
   required to implement assigning indexes and issuing VCs. A key primitive
   in enabling continuable operations is a conflictable write (CW). This
   a write to a database (EDV) where if a document write fails due to a
   conflict in sequence number, the worker can continue its job by assuming
   another worker completed a funtionally equivalent write.

Algorithms:

Note: All of the following algorithms are designed such that they don't need
atomicity, but that they are instead safely "continuable" from any point of
failure. The system continues to make progress even if a single worker
fails, as long as that worker does not create corrupt state. The algorithms
do not enable recovery from corrupt state.

main: The process for issuing a VC with an assigned an index.

0. The worker sets up an in-memory set of list shards (LS), where LS includes
  an RL ID, RL sequence number, BAD, and IAD.
1. Create a CredentialStatusWriter instance `writer`.
2. While a VC has not been successfully written to the database (EDV):
  2.1. Call writer.write(VC).
  2.2. Sign the VC.
  2.3. Attempt to insert the VC in to the database (EDV).
    2.3.1. Note: The database must have a unique index on RL ID + RL index.
  2.4. If a duplicate error occurs, first make sure it is a duplicate error
    due to RL ID + RL index, and if so, loop, otherwise throw.
2. VC has been successfully issued, return it immediately, the receiver of
  the VC response does not need to wait for the following steps to finish.
3. Call writer.finish().
4. Return.

getShard(): Gets a list shard needed to issue a VC. This will be called by
  `writer.write()`.

1. While no LM exists:
  1.1. CW create the LM.
  1.2. If conflict, loop to 1.1.
2. Store the LM in the instance.
3. While true:
  3.1. Call this._readActiveBlockAssignmentDocs(LM).
  3.2. Call this._selectShard(LM, BADs) and if result is not `null`,
    return it.

this._readActiveBlockAssignmentDocs(LM): Reads all active BADs to enable
  choosing an IAD.

1. While active BADs not read:
  1.1. Call _addCapacity(LM, target=1).
  1.2. Read all active BADs.
    1.2.1. If any BAD does not exist, CW create it.
    1.2.2. If any BAD has an RL sequence number that is behind the LM,
      CW update it. If conflict, read the BAD.
    1.2.3. If any BAD has an RL sequence number that is ahead of the
      LM active list item, read the LM and loop to 1.
  1.3. If any BADs have fully assigned blocks of indexes:
    1.3.1. Move BAD IDs to the "inactive" list; if all BADs are fully assigned,
      choose one to leave as active and update its RL ID and RL sequence number.
    1.3.2. CW update LM.
    1.3.3. If conflict, read LM and loop to 1.
    1.3.4. CW update active BAD, if one was updated.
    1.3.5. If conflict, read active BAD. If BAD RL sequence does not match
      LM active list item, read LM and loop to 1.
  1.4. Store read BADs in the instance.

this._selectShard(LM, activeBADs): Select an IAD to use for assigning
  indexes:

1. Select an IAD at random from the BAD blocks with unassigned indexes:
  1.1. Get total number of unassigned blocks and choose randomly.
  1.2. Use choice to find chosen IAD and block index.
2. CW create the IAD if it does not exist or if IAD's RL sequence number
  is behind the one associated with the BAD, CW update the IAD to reset it.
  2.1. If conflict then another worker has chosen the same IAD:
    2.1.1. Track failed attempt to choose an IAD due to conflict.
    2.1.2. Call this._needCapacity(conflicts, BADs):
      2.1.2.1. If result is false, return `null`. Note: A future
        optimization might be to loop again and make a *different* choice,
        but the code must ensure there are more choices to be made.
      2.1.2.2. Otherwise, call _addCapacity(LM, target=BADs+1), clear tracked
        failed attempts, and then return `null`. Note: A future optimization
        might check to see if capacity was added and update BADs accordingly
        without having to return `null`.
3. If the IAD's RL sequence number is ahead, return `null`.
4. If the IAD's indexes have all been assigned:
  4.1. CW update the BAD to indicate the IAD block has been assigned.
  4.2. If conflict, ignore.
  4.3. Return `null`. Note: A future optimization might be to loop
    again and make a *different* choice, but the code must ensure
    there are more choices to be made.
5. Return RL ID, RL sequence number, BAD, and IAD.

this._needCapacity(conflicts, activeBADs):

1. If conflicts > 1 (50/50 chance of conflict is acceptable, but no more) and
   all active BADs have 50% or more of their blocks assigned, return true,
   otherwise return false.

this._addCapacity(target): Add another active BAD (from inactive list or
  a new one):

1. While LM active list size < target:
  1.1. Set `need` = target - LM active list size. Cap `need` by
    min(need, max configured active list size - LM active list size).
  1.2. Set `sn` to the highest RL sequence number amongst active+inactive BADs.
  1.3. Mark up to `need` inactive BADs as active, updating the RL ID and
    RL sequence number (using `++sn` each time). Decrement `need` each time.
  1.4. If `need` > 0, then add `need` more active items as in 1.3.
  1.5. CW update LM.
  1.6. If conflict, read the LM.

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
   many concurrent BADs are created, then as their respective RLs have all of
   their indexes assigned, these BADs will get reset to refer to new RLs. If
   these BADs are not removed from active use, then it could result in RLs
   with very few to zero assigned indexes. This poses a privacy problem which
   this entire revocation scheme was designed to prevent, i.e., as VCs are
   issued, they should be tightly grouped together using a few RLs as
   possible. Spreading index assignment across many mostly empty RLs defeats
   this goal. Therefore, BADs must scale back as appropriate. Removing them
   cleanly from the LM, however, has an atomicity problem: they cannot both
   be removed from the LM document and deleted in a single update. So instead
   of deleting LDs, the LM document expresses two lists, one for active BADs
   and one that expresses inactive BADs.
3. Once a BAD refers to an RL that has assigned all of its indexes, its ID
   is moved from the active list to the inactive list. When the active list
   needs to grow, an inactive BAD is selected, its contents are reset to refer
   to a new RL, and it is moved to the active list.
4. The goal of BADs and IADs is to enable workers to issue many VCs
   concurrently. In order to do this and be able to track assigned indexes
   and recover from any crashed operations, it means that there must be at
   least one IAD for every concurrently issuable VC.
*/
module.exports = class ListManager {
  constructor({rlcBaseUrl, issuer, suite, credentialsCollection} = {}) {
    if(!(rlcBaseUrl && typeof rlcBaseUrl === 'string')) {
      throw new TypeError('"rlcBaseUrl" must be a non-empty string.');
    }
    if(!(credentialsCollection && typeof credentialsCollection === 'object')) {
      throw new TypeError('"credentialsCollection" must be an object.');
    }
    if(!(issuer && typeof issuer === 'string')) {
      throw new TypeError('"issuer" must be a non-empty string.');
    }
    if(!(suite && typeof suite === 'object')) {
      throw new TypeError('"suite" must be an object.');
    }
    this.rlcBaseUrl = rlcBaseUrl;
    this.issuer = issuer;
    this.suite = suite;
    this.credentialsCollection = credentialsCollection;
    this.lmEdvDoc = null;
    this.lmDoc = null;
    this.readActiveList = null;
    this.conflicts = 0;
  }

  async getShard() {
    this.readActiveList = null;
    this.conflicts = 0;
    // initialize edv client, etc.
    await this._init();
    // 1. While no LM exists:
    //   1.1. CW create the LM.
    //   1.2. If conflict, loop to 1.1.
    await this._getListManagementDoc();
    // 2. While true:
    // FIXME: add timeout
    while(true) {
      // 2.1. Call _readActiveBlockAssignmentDocs().
      await this._readActiveBlockAssignmentDocs();
console.log('read active block ass doc');
      // 2.2. Call _selectShard() and if result is not `null`, return it.
      const listShard = await this._selectShard();
      // 2.3. If `listShard` is not `null`, return it.
      if(listShard) {
console.log('return listShared');
        return listShard;
      }
    }
  }

  async _readActiveBlockAssignmentDocs() {
console.log('_readActiveBlockAssignmentDocs');
    // 1. While active BADs not read:
    this.readActiveList = null;
    // FIXME: add timeout
    while(!this.readActiveList) {
console.log('addCapacity being called');
      // 1.1. Call _addCapacity(LM, target=1).
      await this._addCapacity({target: 1});
console.log('added capacity called');
      // 1.2. Read all active BADs.
      const {blockAssignment: {active}} = this.lmDoc.content;
      // 1.2.1. If any BAD does not exist, CW create it.
      let readItems = await Promise.all(active.map(
        item => this._readBlockAssignmentDoc({item})));
console.log({readItems});
      // 1.2.2. If any BAD has an RL sequence number that is behind the LM,
      //   CW update it. If conflict, read the BAD.
      await Promise.all(readItems.map(async x => {
        if(x.blockAssignmentDoc.content.rlSequence < x.item.rlSequence) {
          try {
            // TODO: move into a reset block assignment doc function
            // reset block assignment doc
            const {content} = x.blockAssignmentDoc;
            content.rlSequence = x.item.rlSequence;
            content.blockCount = BLOCK_COUNT;
            content.blockSize = BLOCK_SIZE;
            // TODO: optimize by using string from config or static var
            const bs = new Bitstring({length: content.blockCount});
            content.assignedBlocks = await bs.encodeBits();
            content.assignedBlockCount = 0;
            x.blockAssignmentDoc = await x.blockAssignmentEdvDoc.write(
              {doc: x.blockAssignmentDoc});
          } catch(e) {
            if(e.name !== 'InvalidStateError') {
              throw e;
            }
            x.blockAssignmentDoc = await x.blockAssignmentEdvDoc.read();
          }
        }
      }));
      // 1.2.3. If any BAD has an RL sequence number that is ahead of the
      //   LM active list item, read the LM and loop to 1.
      if(readItems.some(({blockAssignmentDoc: {content}, item}) =>
        content.rlSequence > item.rlSequence)) {
        this.lmDoc = await this.lmEdvDoc.read();
        continue;
      }

      // 1.3. If any BADs have fully assigned blocks of indexes:
      const fullyAssigned = readItems.filter(
        ({blockAssignmentDoc: {content}}) =>
          content.assignedBlockCount === content.blockCount);
      if(fullyAssigned.length > 0) {
        // 1.3.1. Move BAD IDs to the "inactive" list; if all BADs are fully
        //   assigned, choose one to leave as active and update its RL ID and
        //   RL sequence number.
        const {blockAssignment} = this.lmDoc.content;
        const items = fullyAssigned.map(({item}) => item);
        blockAssignment.inactive.push(...items);
        blockAssignment.active = blockAssignment.active.filter(
          x => items.includes(x));
        let toUpdate;
        if(blockAssignment.active.length > 0) {
          // active items remain, will use those
          readItems = readItems.filter(
            ({blockAssignmentDoc: {content}}) =>
              content.assignedBlockCount < content.blockCount);
        } else {
          // no active items remain, must update an inactive one
          blockAssignment.active = blockAssignment.inactive.shift();
          // update LM active list item
          toUpdate = fullyAssigned[0];
          readItems = [toUpdate];
          toUpdate.item.revocationListCredential =
            `${this.rlcBaseUrl}/${uuid()}`;
          toUpdate.item.rlSequence = items.reduce(
            (max, {rlSequence}) => Math.max(max, rlSequence), 0);
          // TODO: move into a reset block assignment doc function
          // reset block assignment doc
          const {content} = toUpdate.blockAssignmentDoc;
          content.rlSequence = toUpdate.item.rlSequence;
          content.blockCount = BLOCK_COUNT;
          content.blockSize = BLOCK_SIZE;
          // TODO: optimize by using string from config or static var
          const bs = new Bitstring({length: content.blockCount});
          content.assignedBlocks = await bs.encodeBits();
          content.assignedBlockCount = 0;
        }
        // 1.3.2. CW update LM.
        try {
          this.lmDoc = await this.lmEdvDoc.write({doc: this.lmDoc});
        } catch(e) {
          if(e.name !== 'InvalidStateError') {
            throw e;
          }
          // 1.3.3. If conflict, read LM and loop to 1.
          this.lmDoc = await this.lmEdvDoc.read();
          continue;
        }
        // 1.3.4. CW update active BAD, if one was updated.
        if(toUpdate) {
          try {
            toUpdate.blockAssignmentDoc =
              await toUpdate.blockAssignmentEdvDoc.write({
                doc: toUpdate.blockAssignmentDoc
              });
          } catch(e) {
            if(e.name !== 'InvalidStateError') {
              throw e;
            }
            // 1.3.5. If conflict, read active BAD. If BAD RL sequence does not
            //  match LM active list item, read LM and loop to 1.
            toUpdate.blockAssignmentDoc =
              await toUpdate.blockAssignmentEdvDoc.read();
            if(toUpdate.blockAssignmentDoc.content.rlSequence !==
              toUpdate.item.rlSequence) {
              this.lmDoc = await this.lmEdvDoc.read();
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
    // 1. Select an IAD at random from the BAD blocks with unassigned indexes:
    //   1.1. Get total number of unassigned blocks and choose randomly.
    //   1.2. Use choice to find chosen IAD and block index.
    const {readActiveList} = this;
    const choice = await _chooseRandom({readActiveList});

    // 2. CW create the IAD if it does not exist or if IAD's RL sequence number
    //   is behind the one associated with the BAD, CW update the IAD to reset
    //   it.
    const {blockIndex, blockAssignmentDoc, blockAssignmentEdvDoc} = choice;
    const {content: {rlSequence}} = blockAssignmentDoc;
    const blockAssignmentDocId = blockAssignmentDoc.content.id;
    let indexAssignmentDoc;
    let indexAssignmentEdvDoc;
    try {
      ({indexAssignmentDoc, indexAssignmentEdvDoc} =
        await this._getIndexAssignmentDoc(
          {blockAssignmentDocId, blockIndex, rlSequence}));
      if(indexAssignmentDoc.content.rlSequence < rlSequence) {
        // TODO: add a function for resetting an IAD
        indexAssignmentDoc.content.rlSequence = rlSequence;
        indexAssignmentDoc.content.nextLocalIndex = 0;
        indexAssignmentEdvDoc = await indexAssignmentEdvDoc.write({
          doc: indexAssignmentEdvDoc
        });
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
      // 2.1.2.1. Otherwise, call _addCapacity(LM, target=BADs+1), clear
      //   tracked failed attempts, and then return `null`. Note: A future
      //   optimization might check to see if capacity was added and update
      //   BADs accordingly without having to return `null`.
      await this._addCapacity({target: readActiveList.length + 1});
      this.conflicts = 0;
      return null;
    }

    // 3. If the IAD's RL sequence number is ahead, return `null`.
    if(indexAssignmentDoc.content.rlSequence > rlSequence) {
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
        await blockAssignmentEdvDoc.write({doc: blockAssignmentDoc});
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

    // 5. Return RL ID, RL sequence number, BAD, and IAD.
    return {...choice, indexAssignmentDoc, indexAssignmentEdvDoc};
  }

  async _addCapacity({target}) {
    // TODO: read max limit from config
    /* Note: A size of 20 when list sizes are 100k and block sizes are 100,
    means there are 1000 blocks to choose from for each active list (20),
    which is 20000 total, so concurrency without collision is ~sqrt(20000),
    which is only 141. But, when a collision happens, another selection can
    be made enabling more concurrency. Every 141 attempts to find a block to
    assign indexes from will result in a collision that requires additional
    work to select a different block, but 20000 total blocks could actually
    be theoretrically serviced concurrently, enabling a maximum of 20000 VCs
    to be issued concurrently. */
    const maxActiveListSize = 20;
    const {rlcBaseUrl} = this;

    // 1. While LM active list size < target:
    let activeListSize = this.lmDoc.content.blockAssignment.active.length;
    while(activeListSize < target) {
      const {blockAssignment} = this.lmDoc.content;
      // 1.1. Set `need` = target - LM active list size. Cap `need` by
      //   min(need, max configured active list size - LM active list size).
      let need = Math.min(target - activeListSize, maxActiveListSize);
      // 1.2. Set `sn` to the highest RL sequence number amongst
      //   active+inactive BADs.
      let sn = blockAssignment.active.reduce(
        (max, x) => Math.max(max, x.rlSequence), 0);
      sn = blockAssignment.inactive.reduce(
        (max, x) => Math.max(max, x.rlSequence), sn);
      // 1.3. Mark up to `need` inactive BADs as active, updating the RL ID and
      //   RL sequence number (using `++sn` each time). Decrement `need` each
      //   time.
      const newActive = blockAssignment.inactive.splice(0, need);
      for(const x of newActive) {
        // TODO: make a helper function for setting RLC ID
        x.revocationListCredential = `${rlcBaseUrl}/${uuid()}`;
        x.rlSequence = ++sn;
      }
      need -= newActive.length;
      blockAssignment.active.push(...newActive);
      // 1.4. If `need` > 0, then add `need` more active items as in 1.3.
      while(need > 0) {
        // TODO: use helper function for this
        blockAssignment.active.push({
          blockAssignmentEdvDocId: await EdvClient.generateId(),
          revocationListCredential: `${rlcBaseUrl}/${uuid()}`,
          rlSequence: ++sn
        });
        need--;
      }
      // 1.5. CW update LM.
      try {
        this.lmDoc = await this.lmEdvDoc.write({doc: this.lmDoc});
      } catch(e) {
        if(e.name !== 'InvalidStateError') {
          throw e;
        }
        // 1.6. If conflict, read the LM.
        this.lmDoc = await this.lmEdvDoc.read();
      }
      activeListSize = this.lmDoc.content.blockAssignment.active.length;
    }
  }

  _needCapacity() {
    // 1. If conflicts > 1 (50/50 chance of conflict is acceptable, but no more)
    //   and all active BADs have 50% or more of their blocks assigned, return
    //   true, otherwise return false.
    const {conflicts, readActiveList} = this;
    if(conflicts < 2) {
      return false;
    }
    return readActiveList.every(({blockAssignmentDoc: {content}}) =>
      (content.assignedBlockCount / content.blockCount) >= 0.5);
  }

  async _getListManagementDoc() {
    // try to find existing LM doc
    const equals = {'content.id': LM_DOC_ID};
    const {credentialsCollection} = this;
    // FIXME: add timeout
    while(true) {
      const results = await credentialsCollection.findDocuments({equals});
      if(results.length === 0) {
        // TODO: create LM doc
        const id = await EdvClient.generateId();
        this.lmEdvDoc = await credentialsCollection.getEdvDocument({id});
        const lmDoc = {
          id,
          content: {
            id: LM_DOC_ID,
            type: 'RevocationList2020ManagementDocument',
            blockAssignment: {
              active: [],
              inactive: []
            }
          },
          meta: {}
        };
        try {
          this.lmDoc = await this.lmEdvDoc.write({doc: lmDoc});
          return;
        } catch(e) {
          // only ignore duplicate error, throw otherwise
          if(e.name !== 'DuplicateError') {
            throw e;
          }
        }
      } else {
        this.lmDoc = results[0];
        this.lmEdvDoc = await credentialsCollection.getEdvDocument(
          {id: this.lmDoc.id});
        return;
      }
    }
  }

  async _readBlockAssignmentDoc({item}) {
    const {credentialsCollection} = this;
    const blockAssignmentEdvDoc = await credentialsCollection.getEdvDocument(
      {id: item.blockAssignmentEdvDocId});
console.log('blockAssignmentDoc fetched', blockAssignmentEdvDoc);
    let blockAssignmentDoc;
    while(!blockAssignmentDoc) {
      try {
        blockAssignmentDoc = await blockAssignmentEdvDoc.read();
console.log('blockAssignmentDoc read');
      } catch(e) {
        if(e.name !== 'NotFoundError') {
          throw e;
        }
console.log('doc was not found');
        const blockCount = BLOCK_COUNT;
        const blockSize = BLOCK_SIZE;

        // doc not found, first ensure revocation list credential exists
        const listSize = blockCount * blockSize;
        const {revocationListCredential} = item;
console.log('calling_ensureRevocationListCredentialExists'); 
        await this._ensureRevocationListCredentialExists(
          {id: revocationListCredential, length: listSize});
console.log('_ensureRevocationListCredentialExists called');
        // next, lazily create BAD
        const bs = new Bitstring({length: blockCount});
        // TODO: move into a reset block assignment doc function
        const doc = {
          id: item.blockAssignmentEdvDocId,
          content: {
            id: `urn:uuid:${uuid()}`,
            type: 'RevocationList2020StatusDocument',
            rlSequence: item.rlSequence,
            blockSize,
            blockCount,
            // TODO: optimize by using string from config or static var
            assignedBlocks: await bs.encodeBits(),
            assignedBlockCount: 0
          },
          meta: {}
        };
        try {
          blockAssignmentDoc = await blockAssignmentEdvDoc.write({doc});
        } catch(e) {
console.error(e);
          if(e.name !== 'DuplicateError') {
            throw e;
          }
          // duplicate, ignore and loop to read doc
        }
      }
    }
console.log('return block');
    return {blockAssignmentEdvDoc, blockAssignmentDoc, item};
  }

  async _ensureRevocationListCredentialExists({id, length}) {
    // try to create RLC credential and EDV doc...
    const {suite, issuer} = this;
    const list = await createList({length});
    const credential = await createRlc({id, list});
    credential.issuer = issuer;
    credential.name = 'Revocation List Credential';
    credential.description =
      'This credential expresses the revocation status for some other ' +
      'credentials in an encoded and compressed list.';
    // express date without milliseconds
    const now = (new Date()).toJSON();
    credential.issuanceDate = `${now.substr(0, now.length - 5)}Z`;
    let verifiableCredential;
console.log('\n', {suite});
console.log('signer capability', suite.signer.capability);
try{
    verifiableCredential = await issue({credential, suite});
} catch(e) {
  console.log('LISt manager issue error');
  console.error(e);
  throw e;
}
console.log('issued');
    let doc = {
      id: await EdvClient.generateId(),
      content: verifiableCredential,
      meta: {}
    };
    const {credentialsCollection} = this;
    const rlcEdvDoc = await credentialsCollection.getEdvDocument({id: doc.id});
    try {
      doc = await rlcEdvDoc.write({doc});
    } catch(e) {
      if(e.name !== 'DuplicateError') {
        throw e;
      }
      // duplicate, ignore as another process created the RLC... get it
      doc = await rlcEdvDoc.read();
    }

    // ensure RLC is published
    const isPublished = await rlcs.exists({id});
    if(!isPublished) {
      const {content: credential, sequence} = doc;
      try {
        // store RLC Doc for public serving
        await rlcs.set({credential, sequence});
      } catch(e) {
        // safe to ignore conflicts, a newer version of the RLC was published
        // than the one that was retrieved
        if(e.name === 'InvalidStateError' || e.name === 'DuplicateError') {
          return;
        }
        throw e;
      }
    }
  }

  async _getIndexAssignmentDoc({
    blockAssignmentDocId, blockIndex, rlSequence
  }) {
    // try to find existing index assignment doc
    const equals = {
      'meta.blockAssignmentDocId': blockAssignmentDocId,
      'meta.blockIndex': blockIndex
    };
    const {credentialsCollection} = this;

    // Note: This implementation is notably different from the
    // `_getListManagementDoc` because when duplicate or conflict errors arise,
    // we want to throw them, not ignore and read.
    const results = await credentialsCollection.findDocuments({equals});
    if(results.length === 0) {
      // TODO: create doc
      const id = await EdvClient.generateId();
      const indexAssignmentEdvDoc =
        await credentialsCollection.getEdvDocument({id});
      let indexAssignmentDoc = {
        id,
        content: {
          id: `urn:uuid:${uuid()}`,
          type: 'RevocationList2020IndexAssignmentDocument',
          rlSequence,
          nextLocalIndex: 0
        },
        meta: {
          blockAssignmentDocId,
          blockIndex
        }
      };
      indexAssignmentDoc = await indexAssignmentEdvDoc.write(
        {doc: indexAssignmentDoc});
      return {indexAssignmentDoc, indexAssignmentEdvDoc};
    } else {
      const [indexAssignmentDoc] = results;
      const indexAssignmentEdvDoc = await credentialsCollection.getEdvDocument(
        {id: indexAssignmentDoc.id});
      return {indexAssignmentDoc, indexAssignmentEdvDoc};
    }
  }

  async _init() {
    const {edvClient} = this.credentialsCollection;

    edvClient.ensureIndex({attribute: 'content.id', unique: true});
    edvClient.ensureIndex({attribute: 'content.type'});
    edvClient.ensureIndex({attribute: 'meta.revoked'});
    edvClient.ensureIndex({
      attribute: ['meta.blockAssignmentDocId', 'meta.blockIndex'],
      unique: true
    });
    edvClient.ensureIndex({
      attribute: [
        'content.credentialStatus.id',
        'content.credentialStatus.revocationListIndex'
      ],
      unique: true
    });
  }
};

async function _chooseRandom({readActiveList}) {
  const unassignedBlockCount = readActiveList.reduce((count, x) => {
    const {blockAssignmentDoc: {content}} = x;
    return count + content.blockCount - content.assignedBlockCount;
  }, 0);
  let choice = Math.floor(Math.random() * unassignedBlockCount);
  // choice is based on total unassigned blocks, now must map the choice
  // to an actual block index by mapping it
  let blockIndex = 0;
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

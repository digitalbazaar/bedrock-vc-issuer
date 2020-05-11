/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {Bitstring} = require('vc-revocation-list');
const ListManager = require('./ListManager.js');
const LRU = require('lru-cache');

// load config defaults
require('./config');

// TODO: make cache size configurable both for number of profile agents
// and for the number of shards for each profile agent
// TODO: possible future optimization: list shards may be able to technically
// be shared across profile agents (just not across issuers) -- if the
// capabilities were to be provided or overwritten when the shard was being
// used instead of just using whatever the cached value is
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

writer.write(VC): Writes credential status information to the
  given VC, overwriting it if it is already present. To be called when
  trying to issue a VC or after a failure to write a VC to the database (EDV)
  because of a duplicate error.

1. If an LS has been assigned to the writer instance (then a duplicate
  error for the VC is being handled):
  1.1. Read the IAD.
  1.2. If the IAD's RL sequence matches the one from the LS and the IAD's
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
4. Use the RL ID and the IAD from the LS to add the RL ID and the next
  unassigned RL index to a VC's credential status section.

writer.finish():

1. Increment instance's IAD's latest index value.
2. CW update IAD. If conflict, ignore.
3. If IAD has had all indexes assigned:
  3.1. Read BAD. If its RL sequence number does not match, return.
  3.2. If the BAD's bitstring has already been updated, return.
  3.3. Update BAD's bitstring and CW update the BAD. If conflict, ignore.
4. Otherwise, add LS back to in-memory set.
5. Clear instance's LS.
*/
module.exports = class CredentialStatusWriter {
  constructor(
    {rlcBaseUrl, issuer, suite, credentialsCollection, profileAgent} = {}) {
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
    if(!(profileAgent && typeof profileAgent === 'object')) {
      throw new TypeError('"profileAgent" must be an object.');
    }
    this.rlcBaseUrl = rlcBaseUrl;
    this.issuer = issuer;
    this.suite = suite;
    this.credentialsCollection = credentialsCollection;
    this.profileAgent = profileAgent;
    this.listShard = null;
  }

  async write({credential} = {}) {
console.log('write');
    if(!(credential && typeof credential === 'object')) {
      throw new TypeError('"credential" must be an object.');
    }

    const {id: profileAgentId} = this.profileAgent;
    let shardQueue = SHARD_QUEUE_CACHE.get(profileAgentId);
    if(!shardQueue) {
      shardQueue = [];
      SHARD_QUEUE_CACHE.set(profileAgentId, shardQueue);
    }

    // 1. If an LS has been assigned to the writer instance (then a duplicate
    // error for the VC is being handled):
    const {listShard} = this;
    if(listShard) {
console.log('found a listShared', listShard);
      const {credentialStatus} = credential;
      if(!(credentialStatus && typeof credentialStatus !== 'object')) {
        throw new TypeError('"credentialStatus" must be an object.');
      }

      // 1.1. Read the IAD.
      const {indexAssignmentEdvDoc, item: {rlSequence}} = listShard;
      const doc = await indexAssignmentEdvDoc.read();

      // 1.2. If the IAD's RL sequence matches the one from the LS and the
      //   IAD's latest assigned index value is behind the index in the VC's
      //   `credentialStatus` field:
      const {revocationListIndex} = credentialStatus;
      const localIndex = _getLocalIndex({listShard, revocationListIndex});
      if(doc.content.rlSequence === rlSequence &&
        doc.content.nextLocalIndex < localIndex) {
        // 1.2.1. Update the latest assigned index value.
        doc.content.nextLocalIndex = localIndex;
        // 1.2.2. CW update the IAD.
        try {
          await indexAssignmentEdvDoc.write({doc});
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
      const {rlcBaseUrl, issuer, suite, credentialsCollection} = this;
      const listManager = new ListManager({
        rlcBaseUrl,
        issuer,
        suite,
        credentialsCollection
      });
console.log('created listMaager');
      this.listShard = await listManager.getShard();
console.log('listManager got shard');
    } else {
      // 3. Otherwise, remove an LS from the set and store it in the
      // instance.
      this.listShard = shardQueue.shift();
    }

    // 4. Use the RL ID and the IAD from the LS to add the RL ID and the next
    //   unassigned RL index to a VC's credential status section.
    const {
      item: {revocationListCredential},
    } = this.listShard;
    const revocationListIndex = _getListIndex({listShard: this.listShard});
    credential.credentialStatus = {
      id: `${revocationListCredential}#${revocationListIndex}`,
      type: 'RevocationList2020Status',
      revocationListCredential,
      revocationListIndex: `${revocationListIndex}`
    };
  }

  async finish() {
    const {listShard} = this;
    if(!listShard) {
      // `finish` should never be called when no `listShard` is available
      throw new Error(
        'Invalid state error; "finish()" must only be called after "write()".');
    }

    // 1. Increment instance's IAD's latest index value.
    const {
      indexAssignmentEdvDoc,
      indexAssignmentDoc,
      blockIndex,
      blockAssignmentDoc: {content: {blockSize}}
    } = listShard;
    const {content: iadContent} = indexAssignmentDoc;
    // 2. CW update IAD. If conflict, ignore.
    try {
      iadContent.nextLocalIndex++;
      listShard.indexAssignmentDoc = await indexAssignmentEdvDoc.write(
        {doc: indexAssignmentDoc});
    } catch(e) {
      // ignore conflict error, throw others
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
    }
    // 3. If IAD has had all indexes assigned:
    if(iadContent.nextLocalIndex === blockSize) {
      // 3.1. Read BAD. If its RL sequence number does not match, return.
      const {blockAssignmentEdvDoc, item: {rlSequence}} = listShard;
      const blockAssignmentDoc = await blockAssignmentEdvDoc.read();
      if(blockAssignmentDoc.content.rlSequence !== rlSequence) {
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
        await blockAssignmentEdvDoc.write({doc: blockAssignmentDoc});
      } catch(e) {
        // ignore conflict error, throw others
        if(e.name !== 'InvalidStateError') {
          throw e;
        }
      }
    } else {
      // 4. Otherwise, add LS back to in-memory set.
      const {id: profileAgentId} = this.profileAgent;
      let shardQueue = SHARD_QUEUE_CACHE.get(profileAgentId);
      if(!shardQueue) {
        shardQueue = [];
        SHARD_QUEUE_CACHE.set(profileAgentId, shardQueue);
      }
      shardQueue.push(listShard);
    }
    // 5. Clear instance's LS.
    this.listShard = null;
  }

  async exists({credential} = {}) {
    if(!(credential && typeof credential === 'object')) {
      throw new TypeError('"credential" must be an object.');
    }
    // FIXME: change to use an `exists` or `count` API that doesn't retrieve
    // and decrypt
    const results = await this.credentialsCollection.findDocuments({
      equals: {'content.credentialStatus.id': credential.credentialStatus.id}
    });
    return results.length !== 0;
  }
};

function _getListIndex({listShard}) {
  const {
    blockIndex,
    indexAssignmentDoc: {content: {nextLocalIndex}},
    blockAssignmentDoc: {content: {blockSize}}
  } = listShard;
  return blockIndex * blockSize + nextLocalIndex;
}

function _getLocalIndex({listShard, revocationListIndex}) {
  const {blockAssignmentDoc: {content: {blockSize}}} = listShard;
  return revocationListIndex % blockSize;
}

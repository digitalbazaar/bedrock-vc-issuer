/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {EdvClient, EdvDocument} = require('edv-client');
const https = require('https');
const instances = require('./instances');
const {util: {BedrockError}} = bedrock;

module.exports = class Collection {
  constructor({type, instance, controllerKey, capability}) {
    this.type = type;
    this.instance = instance;
    this.capability = capability;
    this.controllerKey = controllerKey;
  }

  // FIXME: bikeshed name
  static async getInstance({type, instance}) {
    if(typeof instance === 'string') {
      ({instance} = await instances.get({id: instance}));
    }
    const controllerKey = await instances.getControllerKey({id: instance.id});
    const capability = await instances.getCapability(
      {instance, referenceId: `${instance.id}-edv-configuration`});
    return new Collection({type, instance, controllerKey, capability});
  }

  async create({item, meta}) {
    if(item.type !== this.type) {
      throw new TypeError(`"item.type" (${item.type}) must be "${this.type}".`);
    }
    const {controllerKey, instance, capability} = this;
    const edvDoc = await getEdvDocument(
      {controllerKey, instance, capability});
    const id = await EdvClient.generateId();
    await edvDoc.write({doc: {id, content: item, meta}});
  }

  async get({id, token}) {
    const {controllerKey, instance, capability} = this;
    let results;
    if(id) {
      results = await findDocuments({controllerKey, instance, id, capability});
    } else if(token) {
      results = await findDocuments({
        controllerKey,
        instance,
        equals: {'content.type': this.type, 'meta.token.id': token},
        capability
      });
    } else {
      throw new TypeError('"id" or "token" must be given.');
    }
    if(results.length > 0) {
      return results[0];
    }
    return null;
  }

  async getAll() {
    const {controllerKey, instance, capability} = this;
    const results = await findDocuments(
      {controllerKey, instance, type: this.type, capability});
    return results;
  }

  async update({item, meta, sequence}) {
    if(item.type !== this.type) {
      throw new TypeError(`"item.type" (${item.type}) must be "${this.type}".`);
    }
    const {controllerKey, capability} = this;
    const existing = await this.get({id: item.id});
    const edvDoc = await getEdvDocument(
      {controllerKey, id: existing.id, capability});
    const doc = await edvDoc.read();
    if(sequence !== undefined && sequence !== doc.sequence) {
      const err = new BedrockError(
        'Could not update item; a conflict occurred.',
        'InvalidStateError');
      throw err;
    }
    const updatedDoc = {
      ...doc
    };
    if(item) {
      updatedDoc.content = item;
    }
    if(meta) {
      updatedDoc.meta = meta;
    }
    await edvDoc.write({
      doc: updatedDoc
    });
  }

  async remove({id}) {
    const {controllerKey, capability} = this;
    const existing = await this.get({id});
    if(!existing) {
      return false;
    }
    const edvDoc = await getEdvDocument(
      {controllerKey, id: existing.id, capability});
    return edvDoc.delete();
  }
};

async function getEdvDocument({controllerKey, instance, id, capability}) {
  const client = await getEdvClient({instance});
  const {keyAgreementKey, hmac} = client;
  const invocationSigner = controllerKey;
  const recipients = [{
    header: {kid: keyAgreementKey.id, alg: 'ECDH-ES+A256KW'}
  }];
  return new EdvDocument({
    id, recipients, keyResolver, keyAgreementKey, hmac, capability,
    invocationSigner, client
  });
}

async function getEdvClient({controllerKey, instance}) {
  const [keyAgreementKey, hmac] = await Promise.all([
    controllerKey.getKeyAgreementKey(instance.keys.kak),
    controllerKey.getHmac(instance.keys.hmac)
  ]);
  // TODO: base this off of bedrock.config
  const httpsAgent = new https.Agent({
    rejectUnauthorized: false
  });
  const client = new EdvClient(
    {keyResolver, keyAgreementKey, hmac, httpsAgent});
  // create indexes for documents
  client.ensureIndex({attribute: 'content.id', unique: true});
  client.ensureIndex({attribute: 'content.type'});
  // FIXME: make sure compound indexes work
  // client.ensureIndex(
  //   {attribute: ['content.type', 'meta.token.id'], unique: true});
  client.ensureIndex({attribute: 'meta.token.id', unique: true});
  // TODO: index based on supported credential types for the instance
  // TODO: will need to be able to get all
  // `content.type === 'VerifiableCredential'` and reindex as needed
  return client;
}

async function findDocuments(
  {controllerKey, instance, id, type, equals, has, capability}) {
  if(!(id || type || equals || has)) {
    throw new TypeError('"id", "type", "equals", or "has" must be given.');
  }

  if(!equals) {
    equals = [];
  } else if(Array.isArray(equals)) {
    equals = equals.slice();
  } else if(typeof equals === 'object') {
    equals = [equals];
  } else {
    throw new TypeError('"equals" must be an object or an array of objects.');
  }

  if(id) {
    equals.push({'content.id': id});
  }

  if(type) {
    if(Array.isArray(type)) {
      const query = type.map(type => ({'content.type': type}));
      equals.push(...query);
    } else {
      equals.push({'content.type': type});
    }
  }

  const client = await getEdvClient({controllerKey, instance});
  const results = await client.find(
    {equals, has, capability, invocationSigner: controllerKey});
  return results;
}

// FIXME: make more restrictive, support `did:key` and `did:v1`
async function keyResolver({id}) {
  const remoteDoc = await bedrock.jsonld.documentLoader(id);
  return remoteDoc.document;
}

/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const assert = require('assert-plus');
const axios = require('axios');
const bedrock = require('bedrock');
const brHttpsAgent = require('bedrock-https-agent');
const {EdvClient, EdvDocument} = require('edv-client');
const instances = require('./instances');
const {util: {BedrockError}} = bedrock;

const DEFAULT_HEADERS = {Accept: 'application/ld+json, application/json'};

module.exports = class Collection {
  constructor({type, instance, keystoreAgent, capability}) {
    this.type = type;
    this.instance = instance;
    this.capability = capability;
    this.keystoreAgent = keystoreAgent;
  }

  // FIXME: bikeshed name
  static async getInstance({type, instance}) {
    if(typeof instance === 'string') {
      ({instance} = await instances.get({id: instance}));
    }
    const keystoreAgent = await instances.getKeystoreAgent({id: instance.id});
    const capability = await instances.getCapability(
      {instance, referenceId: `${instance.id}-edv-configuration`});
    return new Collection({type, instance, keystoreAgent, capability});
  }

  async create({item, meta}) {
    if(item.type !== this.type) {
      throw new TypeError(`"item.type" (${item.type}) must be "${this.type}".`);
    }
    const {keystoreAgent, instance, capability} = this;
    const edvDoc = await getEdvDocument({keystoreAgent, instance, capability});
    const id = await EdvClient.generateId();
    await edvDoc.write({doc: {id, content: item, meta}});
  }

  async get({id, token}) {
    const {keystoreAgent, instance, capability} = this;
    let results;
    if(id) {
      results = await findDocuments({keystoreAgent, instance, id, capability});
    } else if(token) {
      results = await findDocuments({
        keystoreAgent,
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
    const {keystoreAgent, instance, capability} = this;
    const results = await findDocuments(
      {keystoreAgent, instance, type: this.type, capability});
    return results;
  }

  async update({item, meta, sequence}) {
    assert.object(item, 'item');
    if(item.type !== this.type) {
      throw new TypeError(`"item.type" (${item.type}) must be "${this.type}".`);
    }
    const {keystoreAgent, instance, capability} = this;
    const existing = await this.get({id: item.id});
    const edvDoc = await getEdvDocument(
      {keystoreAgent, instance, id: existing.id, capability});
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
    if(meta) {
      updatedDoc.meta = meta;
    }
    await edvDoc.write({
      doc: updatedDoc
    });
  }

  async remove({id}) {
    const {keystoreAgent, instance, capability} = this;
    const existing = await this.get({id});
    if(!existing) {
      return false;
    }
    const edvDoc = await getEdvDocument(
      {keystoreAgent, instance, id: existing.id, capability});
    return edvDoc.delete();
  }
};

async function getEdvDocument({keystoreAgent, instance, id, capability}) {
  const client = await getEdvClient({keystoreAgent, instance});
  const {keyAgreementKey, hmac} = client;
  const recipients = [{
    header: {kid: keyAgreementKey.id, alg: 'ECDH-ES+A256KW'}
  }];
  const invocationSigner = await keystoreAgent.getAsymmetricKey(
    instance.keys.zcapKey);
  return new EdvDocument({
    id, recipients, keyResolver, keyAgreementKey, hmac, capability,
    invocationSigner, client
  });
}

async function getEdvClient({keystoreAgent, instance}) {
  const [keyAgreementKey, hmac] = await Promise.all([
    keystoreAgent.getKeyAgreementKey(instance.keys.kak),
    keystoreAgent.getHmac(instance.keys.hmac)
  ]);
  // TODO: base this off of bedrock.config
  const {httpsAgent} = brHttpsAgent;
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
  {keystoreAgent, instance, id, type, equals, has, capability}) {
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

  const client = await getEdvClient({keystoreAgent, instance});
  const invocationSigner = await keystoreAgent.getAsymmetricKey(
    instance.keys.zcapKey);
  const results = await client.find(
    {equals, has, capability, invocationSigner});
  return results;
}

// FIXME: make more restrictive, support `did:key` and `did:v1`
async function keyResolver({id}) {
  const {httpsAgent} = brHttpsAgent;
  const response = await axios.get(id, {headers: DEFAULT_HEADERS, httpsAgent});
  return response.data;
}

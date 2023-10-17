/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {createContextDocumentLoader} from '@bedrock/service-context-store';
import {documentStores} from '@bedrock/service-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';

const {baseUrl} = mockData;
const serviceType = 'vc-issuer';

describe('provision API', () => {
  let capabilityAgent;
  const zcaps = {};
  beforeEach(async () => {
    const secret = '53ad64ce-8e1d-11ec-bb12-10bf48838a41';
    const handle = 'test';
    capabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

    // create keystore for capability agent
    const keystoreAgent = await helpers.createKeystoreAgent(
      {capabilityAgent});

    // generate key for signing VCs (make it a did:key DID for simplicity)
    const assertionMethodKey = await keystoreAgent.generateKey({
      type: 'asymmetric',
      publicAliasTemplate: 'did:key:{publicKeyMultibase}#{publicKeyMultibase}'
    });

    // create EDV for storage (creating hmac and kak in the process)
    const {
      edvConfig,
      hmac,
      keyAgreementKey
    } = await helpers.createEdv({capabilityAgent, keystoreAgent});

    // get service agent to delegate to
    const serviceAgentUrl =
      `${baseUrl}/service-agents/${encodeURIComponent(serviceType)}`;
    const {data: serviceAgent} = await httpClient.get(
      serviceAgentUrl, {agent});

    // delegate edv, hmac, and key agreement key zcaps to service agent
    const {id: edvId} = edvConfig;
    zcaps.edv = await helpers.delegate({
      controller: serviceAgent.id,
      delegator: capabilityAgent,
      invocationTarget: edvId
    });
    const {keystoreId} = keystoreAgent;
    zcaps.hmac = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: hmac.id,
      delegator: capabilityAgent
    });
    zcaps.keyAgreementKey = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: keyAgreementKey.kmsId,
      delegator: capabilityAgent
    });
    zcaps.assertionMethod = await helpers
      .delegate({
        capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
        controller: serviceAgent.id,
        invocationTarget: assertionMethodKey.kmsId,
        delegator: capabilityAgent
      });
  });
  describe('create config', () => {
    it('throws error on missing zcaps', async () => {
      let err;
      let result;
      try {
        result = await helpers.createConfig({capabilityAgent});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.details.errors.should.have.length(1);
      const [error] = err.data.details.errors;
      error.name.should.equal('ValidationError');
      error.message.should.contain(`should have required property 'zcaps'`);
    });
    it('creates a config', async () => {
      let err;
      let result;
      try {
        result = await helpers.createConfig({capabilityAgent, zcaps});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'controller', 'id', 'sequence', 'meterId', 'zcaps', 'issueOptions'
      ]);
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.controller.should.equal(capabilityAgentId);
    });
    it('throws error when creating a config without assertion method zcap',
      async () => {
        let err;
        let result;
        try {
          const zcapsCopy = {...zcaps};
          delete zcapsCopy.assertionMethod;
          result = await helpers.createConfig({
            capabilityAgent, zcaps: zcapsCopy
          });
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.data.name.should.equal('DataError');
        err.data.message.should.equal('Configuration validation failed.');
        const {cause} = err.data.details;
        cause.message.should.equal(
          'No capability available to sign using suite ' +
          '"Ed25519Signature2020".');
      });
    it('creates a config including proper ipAllowList', async () => {
      const ipAllowList = ['127.0.0.1/32', '::1/128'];

      let err;
      let result;
      try {
        result = await helpers.createConfig(
          {capabilityAgent, ipAllowList, zcaps});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'controller', 'id', 'ipAllowList', 'sequence', 'meterId', 'zcaps',
        'issueOptions'
      ]);
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.controller.should.equal(capabilityAgentId);
      result.ipAllowList.should.eql(ipAllowList);
    });
    it('throws error on invalid ipAllowList', async () => {
      // this is not a valid CIDR
      const ipAllowList = ['127.0.0.1/33'];

      let err;
      let result;
      try {
        result = await helpers.createConfig(
          {capabilityAgent, ipAllowList, zcaps});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.details.errors.should.have.length(1);
      const [error] = err.data.details.errors;
      error.name.should.equal('ValidationError');
      error.message.should.contain('should match pattern');
      error.details.path.should.equal('.ipAllowList[0]');
    });
    it('throws error on invalid ipAllowList', async () => {
      // an empty allow list is invalid
      const ipAllowList = [];

      let err;
      let result;
      try {
        result = await helpers.createConfig(
          {capabilityAgent, ipAllowList, zcaps});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.details.errors.should.have.length(1);
      const [error] = err.data.details.errors;
      error.name.should.equal('ValidationError');
      error.message.should.contain('should NOT have fewer than 1 items');
      error.details.path.should.equal('.ipAllowList');
    });
    it('throws error on no "sequence"', async () => {
      const url = `${bedrock.config.server.baseUri}/issuers`;
      const config = {
        controller: capabilityAgent.id
      };

      let err;
      let result;
      try {
        result = await httpClient.post(url, {agent, json: config});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.type.should.equal('ValidationError');
      err.data.message.should.equal(
        'A validation error occured in the \'createConfigBody\' validator.');
    });
  });

  describe('get config', () => {
    it('gets a config', async () => {
      const config = await helpers.createConfig(
        {capabilityAgent, zcaps});
      let err;
      let result;
      try {
        result = await helpers.getConfig({id: config.id, capabilityAgent});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'controller', 'id', 'sequence', 'meterId', 'zcaps', 'issueOptions'
      ]);
      result.id.should.equal(config.id);
    });
    it('gets a config w/oauth2', async () => {
      const config = await helpers.createConfig(
        {capabilityAgent, zcaps, oauth2: true});
      const accessToken = await helpers.getOAuth2AccessToken(
        {configId: config.id, action: 'read', target: '/'});
      let err;
      let result;
      try {
        result = await helpers.getConfig({id: config.id, accessToken});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'authorization', 'controller', 'id', 'sequence', 'meterId', 'zcaps',
        'issueOptions'
      ]);
      result.id.should.equal(config.id);
    });
    it('gets a config with ipAllowList', async () => {
      const ipAllowList = ['127.0.0.1/32', '::1/128'];

      const config = await helpers.createConfig(
        {capabilityAgent, ipAllowList, zcaps});
      let err;
      let result;
      try {
        result = await helpers.getConfig({id: config.id, capabilityAgent});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'controller', 'id', 'ipAllowList', 'sequence', 'meterId', 'zcaps',
        'issueOptions'
      ]);
      result.should.have.property('id');
      result.id.should.equal(config.id);
      result.ipAllowList.should.eql(ipAllowList);
    });
    it('returns NotAllowedError for invalid source IP', async () => {
      const ipAllowList = ['8.8.8.8/32'];

      const config = await helpers.createConfig(
        {capabilityAgent, ipAllowList, zcaps});
      let err;
      let result;
      try {
        result = await helpers.getConfig({id: config.id, capabilityAgent});
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.status.should.equal(403);
      err.data.type.should.equal('NotAllowedError');
    });
  }); // get config

  describe('update config', () => {
    it('updates a config', async () => {
      // create new capability agent to change config `controller` to
      const capabilityAgent2 = await CapabilityAgent.fromSecret(
        {secret: 's2', handle: 'h2'});

      let err;
      let result;
      let existingConfig;
      try {
        existingConfig = result = await helpers.createConfig(
          {capabilityAgent, zcaps});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.property('id');
      result.should.have.property('sequence');
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.should.have.property('controller');
      result.controller.should.equal(capabilityAgentId);

      // this update does not change the `meterId`
      const {id: url} = result;
      const newConfig = {
        ...existingConfig,
        controller: capabilityAgent2.id,
        sequence: 1
      };

      err = null;
      result = null;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({url, json: newConfig});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result.data);
      result.status.should.equal(200);
      result.data.should.have.keys([
        'id', 'controller', 'sequence', 'meterId', 'zcaps', 'issueOptions'
      ]);
      const expectedConfig = {
        ...existingConfig,
        ...newConfig
      };
      result.data.should.eql(expectedConfig);

      // should fail to retrieve the config now that controller
      // has changed
      err = null;
      result = null;
      try {
        result = await helpers.getConfig(
          {id: newConfig.id, capabilityAgent});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.status.should.equal(403);
      err.data.type.should.equal('NotAllowedError');

      // retrieve the config to confirm update was effective
      err = null;
      result = null;
      try {
        result = await helpers.getConfig(
          {id: newConfig.id, capabilityAgent: capabilityAgent2});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.eql(expectedConfig);
    });
    it('updates a config enabling oauth2', async () => {
      let err;
      let result;
      let existingConfig;
      try {
        existingConfig = result = await helpers.createConfig(
          {capabilityAgent, zcaps});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.property('id');
      result.should.have.property('sequence');
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.should.have.property('controller');
      result.controller.should.equal(capabilityAgentId);

      // should fail to retrieve the config since `oauth2` is not yet
      // enabled
      const accessToken = await helpers.getOAuth2AccessToken(
        {configId: existingConfig.id, action: 'read', target: '/'});
      err = null;
      result = null;
      try {
        result = await helpers.getConfig(
          {id: existingConfig.id, accessToken});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.status.should.equal(403);
      err.data.type.should.equal('NotAllowedError');

      // this update adds `oauth2` authz config
      const {baseUri} = bedrock.config.server;
      let newConfig = {
        ...existingConfig,
        sequence: 1,
        authorization: {
          oauth2: {
            issuerConfigUrl: `${baseUri}${mockData.oauth2IssuerConfigRoute}`
          }
        }
      };
      err = null;
      result = null;
      try {
        const url = existingConfig.id;
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({url, json: newConfig});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result.data);
      result.status.should.equal(200);
      result.data.should.have.keys([
        'id', 'controller', 'sequence', 'meterId', 'authorization', 'zcaps',
        'issueOptions'
      ]);
      let expectedConfig = {
        ...existingConfig,
        ...newConfig
      };
      result.data.should.eql(expectedConfig);

      // retrieve the config using `oauth2` to confirm update was effective
      err = null;
      result = null;
      try {
        result = await helpers.getConfig({id: newConfig.id, accessToken});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.eql(expectedConfig);

      // this update removes `oauth2` authz config
      newConfig = {
        ...existingConfig,
        sequence: 2
      };
      delete newConfig.authorization;
      err = null;
      result = null;
      try {
        const url = existingConfig.id;
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({url, json: newConfig});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result.data);
      result.status.should.equal(200);
      result.data.should.have.keys([
        'id', 'controller', 'sequence', 'meterId', 'zcaps', 'issueOptions'
      ]);
      expectedConfig = {
        ...existingConfig,
        ...newConfig
      };
      result.data.should.eql(expectedConfig);

      // should fail to retrieve the config since `oauth2` is no longer
      // enabled
      err = null;
      result = null;
      try {
        result = await helpers.getConfig(
          {id: existingConfig.id, accessToken});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.status.should.equal(403);
      err.data.type.should.equal('NotAllowedError');
    });
    it('rejects config update for an invalid zcap', async () => {
      const capabilityAgent2 = await CapabilityAgent.fromSecret(
        {secret: 's2', handle: 'h2'});

      let err;
      let result;
      try {
        result = await helpers.createConfig(
          {capabilityAgent, zcaps});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.property('id');
      result.should.have.property('sequence');
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.should.have.property('controller');
      result.controller.should.equal(capabilityAgentId);

      const {id: url} = result;
      const newConfig = {
        ...result,
        controller: capabilityAgent2.id,
        sequence: 1
      };

      err = null;
      result = null;
      try {
        // the capability invocation here is signed by `capabilityAgent2`
        // which is not the `controller` of the config
        const zcapClient = helpers.createZcapClient({
          capabilityAgent: capabilityAgent2
        });
        result = await zcapClient.write({url, json: newConfig});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.status.should.equal(403);
      err.data.type.should.equal('NotAllowedError');
      err.data.cause.message.should.contain(
        'The capability controller does not match the verification method ' +
        '(or its controller) used to invoke.');
    });
    it('rejects config update with an invalid sequence', async () => {
      const capabilityAgent2 = await CapabilityAgent.fromSecret(
        {secret: 's2', handle: 'h2'});

      let err;
      let result;
      try {
        result = await helpers.createConfig(
          {capabilityAgent, zcaps});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.property('id');
      result.should.have.property('sequence');
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.should.have.property('controller');
      result.controller.should.equal(capabilityAgentId);

      const {id: url} = result;
      const newConfig = {
        ...result,
        controller: capabilityAgent2.id,
        // the proper sequence would be 1
        sequence: 10
      };

      err = null;
      result = null;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({url, json: newConfig});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.status.should.equal(409);
      err.data.type.should.equal('InvalidStateError');
    });
    describe('updates with ipAllowList', () => {
      it('updates a config with ipAllowList', async () => {
        const capabilityAgent2 = await CapabilityAgent.fromSecret(
          {secret: 's2', handle: 'h2'});

        const ipAllowList = ['127.0.0.1/32', '::1/128'];

        let err;
        let result;
        let existingConfig;
        try {
          existingConfig = result = await helpers.createConfig(
            {capabilityAgent, ipAllowList, zcaps});
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result);
        result.should.have.property('id');
        result.should.have.property('sequence');
        result.sequence.should.equal(0);
        const {id: capabilityAgentId} = capabilityAgent;
        result.should.have.property('controller');
        result.controller.should.equal(capabilityAgentId);

        const {id: url} = result;
        const newConfig = {
          ...existingConfig,
          controller: capabilityAgent2.id,
          ipAllowList,
          sequence: 1
        };

        err = null;
        result = null;
        try {
          const zcapClient = helpers.createZcapClient({capabilityAgent});
          result = await zcapClient.write({url, json: newConfig});
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result.data);
        result.status.should.equal(200);
        result.data.should.have.keys([
          'id', 'controller', 'sequence', 'meterId', 'ipAllowList', 'zcaps',
          'issueOptions'
        ]);
        const expectedConfig = {
          ...existingConfig,
          ...newConfig
        };
        result.data.should.eql(expectedConfig);

        // should fail to retrieve the config now that controller
        // has changed
        err = null;
        result = null;
        try {
          result = await helpers.getConfig(
            {id: newConfig.id, capabilityAgent});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.status.should.equal(403);
        err.data.type.should.equal('NotAllowedError');

        // retrieve the config to confirm update was effective
        err = null;
        result = null;
        try {
          result = await helpers.getConfig(
            {id: newConfig.id, capabilityAgent: capabilityAgent2});
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result);
        result.should.eql(expectedConfig);
      });
      it('returns NotAllowedError for invalid source IP', async () => {
        const capabilityAgent2 = await CapabilityAgent.fromSecret(
          {secret: 's2', handle: 'h2'});

        const ipAllowList = ['8.8.8.8/32'];

        let err;
        let result;
        try {
          result = await helpers.createConfig(
            {capabilityAgent, ipAllowList, zcaps});
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result);
        result.should.have.property('id');
        result.should.have.property('sequence');
        result.sequence.should.equal(0);
        const {id: capabilityAgentId} = capabilityAgent;
        result.should.have.property('controller');
        result.controller.should.equal(capabilityAgentId);

        const {id: url} = result;
        const newConfig = {
          ...result,
          controller: capabilityAgent2.id,
          ipAllowList,
          sequence: 1
        };

        err = null;
        result = null;
        try {
          const zcapClient = helpers.createZcapClient({capabilityAgent});
          result = await zcapClient.write({url, json: newConfig});
        } catch(e) {
          err = e;
        }
        should.not.exist(result);
        should.exist(err);
        err.status.should.equal(403);
        err.data.type.should.equal('NotAllowedError');
      });
    }); // updates with ipAllowList
  }); // end update config

  describe('revocations', () => {
    it('throws error with invalid zcap when revoking', async () => {
      const config = await helpers.createConfig({capabilityAgent, zcaps});
      const zcap = {
        '@context': ['https://w3id.org/zcap/v1'],
        id: 'urn:uuid:895d985c-8e20-11ec-b82f-10bf48838a41',
        proof: {}
      };

      const url =
        `${config.id}/zcaps/revocations/${encodeURIComponent(zcap.id)}`;

      let err;
      let result;
      try {
        result = await httpClient.post(url, {agent, json: zcap});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.type.should.equal('ValidationError');
      err.data.message.should.equal(
        'A validation error occured in the \'Delegated ZCAP\' validator.');
    });
    it('revokes a zcap', async () => {
      const config = await helpers.createConfig({capabilityAgent, zcaps});

      const capabilityAgent2 = await CapabilityAgent.fromSecret(
        {secret: 's2', handle: 'h2'});

      const zcap = await helpers.delegate({
        controller: capabilityAgent2.id,
        invocationTarget: config.id,
        delegator: capabilityAgent
      });

      // zcap should work to get config
      const zcapClient = helpers.createZcapClient(
        {capabilityAgent: capabilityAgent2});
      const {data} = await zcapClient.read({capability: zcap});
      data.should.have.keys([
        'controller', 'id', 'sequence', 'meterId', 'zcaps', 'issueOptions'
      ]);
      data.id.should.equal(config.id);

      // revoke zcap
      await helpers.revokeDelegatedCapability({
        serviceObjectId: config.id,
        capabilityToRevoke: zcap,
        invocationSigner: capabilityAgent.getSigner()
      });

      // now getting config should fail
      let err;
      try {
        await zcapClient.read({capability: zcap});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.data.type.should.equal('NotAllowedError');
    });
  }); // end revocations

  describe('contexts', () => {
    it('fails to inserts a context due to bad zcap', async () => {
      const config = await helpers.createConfig({capabilityAgent, zcaps});

      // insert `context`
      const contextId = 'https://test.example/v1';
      const context = {'@context': {term: 'https://test.example#term'}};
      const client = helpers.createZcapClient({capabilityAgent});
      const url = `${config.id}/contexts`;

      // intentionally bad root zcap here; the root zcap must be for the
      // service object config, not `/contexts` URL as it is set here
      const rootZcap = `urn:zcap:root:${encodeURIComponent(url)}`;

      let err;
      try {
        await client.write({
          url, json: {id: contextId, context},
          capability: rootZcap
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.data.type.should.equal('NotAllowedError');
    });
    it('inserts a context', async () => {
      const config = await helpers.createConfig({capabilityAgent, zcaps});
      const rootZcap = `urn:zcap:root:${encodeURIComponent(config.id)}`;

      // insert `context`
      const contextId = 'https://test.example/v1';
      const context = {'@context': {term: 'https://test.example#term'}};
      const client = helpers.createZcapClient({capabilityAgent});
      const url = `${config.id}/contexts`;

      let err;
      let response;
      try {
        response = await client.write({
          url, json: {id: contextId, context},
          capability: rootZcap
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(response);
      should.exist(response.data);
      response.data.should.deep.equal({
        id: 'https://test.example/v1',
        context,
        sequence: 0
      });
    });
    it('throws error on no "context"', async () => {
      const config = await helpers.createConfig({capabilityAgent, zcaps});
      const rootZcap = `urn:zcap:root:${encodeURIComponent(config.id)}`;

      const contextId = 'https://test.example/v1';
      const client = helpers.createZcapClient({capabilityAgent});
      const url = `${config.id}/contexts`;

      let err;
      let result;
      try {
        await client.write({url, json: {id: contextId}, capability: rootZcap});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.type.should.equal('ValidationError');
      err.data.message.should.equal(
        'A validation error occured in the \'createContextBody\' validator.');
    });
    it('updates a context', async () => {
      const config = await helpers.createConfig({capabilityAgent, zcaps});
      const rootZcap = `urn:zcap:root:${encodeURIComponent(config.id)}`;

      // insert `context`
      const contextId = 'https://test.example/v1';
      const context = {'@context': {term: 'https://test.example#term'}};
      const client = helpers.createZcapClient({capabilityAgent});
      let url = `${config.id}/contexts`;
      await client.write({
        url, json: {id: contextId, context},
        capability: rootZcap
      });

      // update `context`
      context['@context'].term2 = 'https://test.example#term2';
      url = `${url}/${encodeURIComponent(contextId)}`;
      let err;
      let response;
      try {
        response = await client.write({
          url, json: {id: contextId, context, sequence: 1},
          capability: rootZcap
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(response);
      should.exist(response.data);
      response.data.should.deep.equal({
        id: 'https://test.example/v1',
        context,
        sequence: 1
      });
    });
    it('fails to update a context with wrong sequence', async () => {
      const config = await helpers.createConfig({capabilityAgent, zcaps});
      const rootZcap = `urn:zcap:root:${encodeURIComponent(config.id)}`;

      // insert `context`
      const contextId = 'https://test.example/v1';
      const context = {'@context': {term: 'https://test.example#term'}};
      const client = helpers.createZcapClient({capabilityAgent});
      let url = `${config.id}/contexts`;
      await client.write({
        url, json: {id: contextId, context},
        capability: rootZcap
      });

      // update `context`
      context['@context'].term2 = 'https://test.example#term2';
      url = `${url}/${encodeURIComponent(contextId)}`;
      let err;
      let response;
      try {
        response = await client.write({
          url, json: {id: contextId, context, sequence: 10},
          capability: rootZcap
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(response);
      err.data.type.should.equal('InvalidStateError');
    });
    it('gets a context', async () => {
      const config = await helpers.createConfig({capabilityAgent, zcaps});
      const rootZcap = `urn:zcap:root:${encodeURIComponent(config.id)}`;

      // insert `context`
      const contextId = 'https://test.example/v1';
      const context = {'@context': {term: 'https://test.example#term'}};
      const client = helpers.createZcapClient({capabilityAgent});
      let url = `${config.id}/contexts`;
      await client.write({
        url, json: {id: contextId, context},
        capability: rootZcap
      });

      url = `${url}/${encodeURIComponent(contextId)}`;
      let err;
      let response;
      try {
        response = await client.read({
          url, capability: rootZcap
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(response);
      should.exist(response.data);
      response.data.should.deep.equal({
        id: 'https://test.example/v1',
        context,
        sequence: 0
      });
    });
    it('gets a context with a context document loader', async () => {
      const config = await helpers.createConfig({capabilityAgent, zcaps});
      const rootZcap = `urn:zcap:root:${encodeURIComponent(config.id)}`;

      // insert `context`
      const contextId = 'https://test.example/v1';
      const context = {'@context': {term: 'https://test.example#term'}};
      const client = helpers.createZcapClient({capabilityAgent});
      const url = `${config.id}/contexts`;
      await client.write({
        url, json: {id: contextId, context},
        capability: rootZcap
      });

      const documentLoader = await createContextDocumentLoader({
        config, serviceType
      });

      let err;
      let result;
      try {
        result = await documentLoader(contextId);
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      should.exist(result.documentUrl);
      should.exist(result.document);
      result.documentUrl.should.equal(contextId);
      result.document.should.deep.equal(context);
    });
    it('fails to get a context with wrong meta type', async () => {
      const config = await helpers.createConfig({capabilityAgent, zcaps});
      const rootZcap = `urn:zcap:root:${encodeURIComponent(config.id)}`;

      // insert `context`
      const contextId = 'https://test.example/v1';
      const context = {'@context': {term: 'https://test.example#term'}};
      const client = helpers.createZcapClient({capabilityAgent});
      const url = `${config.id}/contexts`;
      await client.write({
        url, json: {id: contextId, context},
        capability: rootZcap
      });

      // get context successfully
      const documentLoader = await createContextDocumentLoader({
        config, serviceType
      });

      let err;
      let result;
      try {
        result = await documentLoader(contextId);
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      should.exist(result.documentUrl);
      should.exist(result.document);
      result.documentUrl.should.equal(contextId);
      result.document.should.deep.equal(context);

      // now erroneously update context to new meta type
      const {documentStore} = await documentStores.get({config, serviceType});
      await documentStore.upsert({
        content: {id: contextId, context},
        meta: {type: 'different'}
      });

      try {
        await documentLoader(contextId);
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.name.should.equal('NotFoundError');
    });
  }); // end contexts
});

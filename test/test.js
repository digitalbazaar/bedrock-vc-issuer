/*!
 * Copyright (c) 2016-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {getServiceIdentities} from '@bedrock/app-identity';
import {handlers} from '@bedrock/meter-http';
import '@bedrock/ssm-mongodb';
import '@bedrock/kms';
import '@bedrock/https-agent';
import '@bedrock/meter';
import '@bedrock/meter-usage-reporter';
import '@bedrock/server';
import '@bedrock/kms-http';
import '@bedrock/edv-storage';
import '@bedrock/vc-issuer';

import {mockData} from './mocha/mock.data.js';

bedrock.events.on('bedrock.init', async () => {
  /* Handlers need to be added before `bedrock.start` is called. These are
  no-op handlers to enable meter usage without restriction */
  handlers.setCreateHandler({
    handler({meter} = {}) {
      // use configured meter usage reporter as service ID for tests
      const clientName = mockData.productIdMap.get(meter.product.id);
      const serviceIdentites = getServiceIdentities();
      const serviceIdentity = serviceIdentites.get(clientName);
      if(!serviceIdentity) {
        throw new Error(`Could not find identity "${clientName}".`);
      }
      meter.serviceId = serviceIdentity.id;
      return {meter};
    }
  });
  handlers.setUpdateHandler({handler: ({meter} = {}) => ({meter})});
  handlers.setRemoveHandler({handler: ({meter} = {}) => ({meter})});
  handlers.setUseHandler({handler: ({meter} = {}) => ({meter})});
});

// mock oauth2 authz server routes
bedrock.events.on('bedrock-express.configure.routes', app => {
  app.get(mockData.oauth2IssuerConfigRoute, (req, res) => {
    res.json(mockData.oauth2Config);
  });
  app.get('/oauth2/jwks', (req, res) => {
    res.json(mockData.jwks);
  });
});

import '@bedrock/test';
bedrock.start();

/*
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {createZcapClient} from './helpers.js';

export async function assertStoredCredential({
  configId, credentialId, zcapClient, capability, expectedCredential} = {}) {
  const url = `${configId}/credentials/${encodeURIComponent(credentialId)}`;

  let error;
  let result;
  try {
    result = await zcapClient.read({url, capability});
  } catch(e) {
    error = e;
  }
  assertNoError(error);
  should.exist(result.data);
  should.exist(result.data.verifiableCredential);
  result.data.verifiableCredential.should.deep.equal(expectedCredential);

  // fail to fetch using unauthorized party
  {
    let error;
    let result;
    try {
      const secret = crypto.randomUUID();
      const handle = 'test';
      const capabilityAgent = await CapabilityAgent.fromSecret({
        secret, handle
      });
      const zcapClient = createZcapClient({capabilityAgent});
      result = await zcapClient.read({url, capability});
    } catch(e) {
      error = e;
    }
    should.not.exist(result);
    should.exist(error?.data?.name);
    error.status.should.equal(403);
    error.data.name.should.equal('NotAllowedError');
  }
}

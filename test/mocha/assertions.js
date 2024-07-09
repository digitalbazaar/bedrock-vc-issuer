/*
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {createZcapClient} from './helpers.js';

const VC_CONTEXT_V1 = 'https://www.w3.org/2018/credentials/v1';
const VC_CONTEXT_V2 = 'https://www.w3.org/ns/credentials/v2';

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

export async function issueAndAssert({
  configId, credential, issueOptions, zcapClient, capability
}) {
  const version1 = credential['@context'].includes(VC_CONTEXT_V1);
  const version2 = credential['@context'].includes(VC_CONTEXT_V2);

  let error;
  let result;
  try {
    result = await zcapClient.write({
      url: `${configId}/credentials/issue`,
      capability,
      json: {
        credential,
        options: issueOptions
      }
    });
  } catch(e) {
    error = e;
  }
  assertNoError(error);
  should.exist(result.data);
  should.exist(result.data.verifiableCredential);
  const {verifiableCredential} = result.data;
  verifiableCredential.should.be.an('object');
  should.exist(verifiableCredential['@context']);
  should.exist(verifiableCredential.id);
  should.exist(verifiableCredential.type);
  should.exist(verifiableCredential.issuer);
  if(version1) {
    verifiableCredential['@context'].includes(VC_CONTEXT_V1).should.equal(true);
    should.exist(verifiableCredential.issuanceDate);
  }
  if(version2) {
    verifiableCredential['@context'].includes(VC_CONTEXT_V2).should.equal(true);
  }
  should.exist(verifiableCredential.credentialSubject);
  verifiableCredential.credentialSubject.should.be.an('object');
  should.exist(verifiableCredential.proof);
  verifiableCredential.proof.should.be.an('object');

  return {result, verifiableCredential};
}

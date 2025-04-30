/*!
 * Copyright (c) 2020-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import {createRequire} from 'node:module';
import {mockData} from './mock.data.js';
import {randomUUID as uuid} from 'node:crypto';

const require = createRequire(import.meta.url);

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');

describe('issue using VC-JWT format w/status list support', () => {
  let assertionMethodKeyId;
  let capabilityAgent;
  let did;
  let zcaps;
  let issuerCreateStatusListZcap;
  let issuerConfig;
  let issuerId;
  let issuerRootZcap;
  let statusConfig;
  let statusId;
  let statusRootZcap;
  beforeEach(async () => {
    // use envelope-based security
    const envelope = {
      format: 'VC-JWT',
      algorithm: 'P-256'
    };

    // generate a `did:web` DID for the issuer
    const {host} = bedrock.config.server;
    const localId = uuid();
    did = `did:web:${encodeURIComponent(host)}:did-web:${localId}`;

    // provision dependencies
    ({
      capabilityAgent, zcaps,
      statusConfig, issuerCreateStatusListZcap
    } = await helpers.provisionDependencies({
      did, envelope, suiteOptions: {
        statusOptions: {
          envelope
        }
      },
      zcaps: true
    }));

    // create issue options
    const issueOptions = {
      issuer: did,
      envelope: {
        format: envelope.format,
        zcapReferenceIds: envelope.zcapReferenceIds
      }
    };

    // create `did:web` DID document for issuer
    const didDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
        'https://w3id.org/security/multikey/v1'
      ],
      id: did,
      verificationMethod: [],
      assertionMethod: []
    };
    for(const {assertionMethodKey} of [envelope]) {
      const description = await assertionMethodKey.getKeyDescription();
      delete description['@context'];
      didDocument.verificationMethod.push(description);
      didDocument.assertionMethod.push(description.id);
      assertionMethodKeyId = description.id;
    }
    // add DID doc to map with DID docs to be served
    mockData.didWebDocuments.set(localId, didDocument);

    // create issuer instance w/ bitstring status list options
    // w/ revocation status purpose
    const statusListOptions = [{
      type: 'BitstringStatusList',
      statusPurpose: 'revocation',
      zcapReferenceIds: {
        createCredentialStatusList: 'createCredentialStatusList'
      }
    }];
    const newZcaps = {
      ...zcaps,
      createCredentialStatusList: issuerCreateStatusListZcap
    };
    issuerConfig = await helpers.createIssuerConfig({
      capabilityAgent, zcaps: newZcaps, statusListOptions, issueOptions
    });
    issuerId = issuerConfig.id;
    issuerRootZcap = `urn:zcap:root:${encodeURIComponent(issuerId)}`;
    statusId = statusConfig.id;
    statusRootZcap = `urn:zcap:root:${encodeURIComponent(statusConfig.id)}`;
  });
  it('issues a VC-JWT VC 1.1 credential', async () => {
    const credential = structuredClone(mockCredential);
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${issuerId}/credentials/issue`,
        capability: issuerRootZcap,
        json: {
          credential,
          options: {
            extraInformation: 'abc'
          }
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
    verifiableCredential.type.should.equal('EnvelopedVerifiableCredential');
    verifiableCredential.id.should.be.a('string');
    verifiableCredential.id.should.include('data:application/jwt,');

    // assert JWT contents
    const jwt = verifiableCredential.id.slice('data:application/jwt,'.length);
    const split = jwt.split('.');
    split.length.should.equal(3);
    const header = JSON.parse(Buffer.from(split[0], 'base64url').toString());
    const payload = JSON.parse(Buffer.from(split[1], 'base64url').toString());
    header.kid.should.equal(assertionMethodKeyId);
    header.alg.should.equal('ES256');
    payload.iss.should.equal(did);
    payload.jti.should.equal(credential.id);
    payload.sub.should.equal(credential.credentialSubject.id);
    should.exist(payload.vc);
    // assert credential status is set in payload
    should.exist(payload.vc.credentialStatus);
    // assert other properties
    const expectedCredential = {
      ...credential,
      '@context': [
        ...credential['@context'],
        'https://www.w3.org/ns/credentials/status/v1'
      ],
      issuer: did,
      issuanceDate: payload.vc.issuanceDate ?? 'error: missing date'
    };
    const moduloStatus = {...payload.vc};
    delete moduloStatus.credentialStatus;
    moduloStatus.should.deep.equal(expectedCredential);
  });
  it('updates a BitstringStatusList revocation credential status', async () => {
    // first issue VC
    const credential = structuredClone(mockCredential);
    const zcapClient = helpers.createZcapClient({capabilityAgent});
    let {data: {verifiableCredential}} = await zcapClient.write({
      url: `${issuerId}/credentials/issue`,
      capability: issuerRootZcap,
      json: {credential}
    });

    // parse enveloped VC as needed
    if(verifiableCredential.type === 'EnvelopedVerifiableCredential') {
      verifiableCredential = helpers.parseEnvelope({verifiableCredential});
    }

    // get VC status
    const statusInfo = await helpers.getCredentialStatus(
      {verifiableCredential});
    let {status} = statusInfo;
    status.should.equal(false);

    // then revoke VC
    let error;
    try {
      const {statusListOptions: [{indexAllocator}]} = issuerConfig;
      await zcapClient.write({
        url: `${statusId}/credentials/status`,
        capability: statusRootZcap,
        json: {
          credentialId: verifiableCredential.id,
          indexAllocator,
          credentialStatus: verifiableCredential.credentialStatus,
          status: true
        }
      });
    } catch(e) {
      error = e;
    }
    assertNoError(error);

    // force refresh of new SLC
    await zcapClient.write({
      url: `${statusInfo.statusListCredential}?refresh=true`,
      capability: statusRootZcap,
      json: {}
    });

    // check status of VC has changed
    ({status} = await helpers.getCredentialStatus(
      {verifiableCredential}));
    status.should.equal(true);

    // FIXME: check returned status VC envelope and ensure it is
    // JWT-encoded
  });
});

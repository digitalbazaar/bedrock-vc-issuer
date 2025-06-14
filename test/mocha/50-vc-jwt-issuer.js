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

describe('issue using VC-JWT format', () => {
  let assertionMethodKeyId;
  let capabilityAgent;
  let did;
  let zcaps;
  let noStatusListIssuerId;
  let noStatusListIssuerRootZcap;
  beforeEach(async () => {
    // use envelope-based security
    const envelope = {
      format: 'VC-JWT',
      algorithm: 'P-256',
      // works with or without options
      /*options: {
        alg: 'ES256'
      }*/
    };

    // generate a `did:web` DID for the issuer
    const {host} = bedrock.config.server;
    const localId = uuid();
    did = `did:web:${encodeURIComponent(host)}:did-web:${localId}`;

    // provision dependencies
    ({capabilityAgent, zcaps} = await helpers.provisionDependencies(
      {did, envelope, status: false, zcaps: true}));

    // create issue options
    const issueOptions = {
      issuer: did,
      envelope: {
        format: envelope.format,
        options: envelope.options,
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

    // create issuer instance w/ no status list options
    const noStatusListIssuerConfig = await helpers.createIssuerConfig({
      capabilityAgent, zcaps, issueOptions
    });
    noStatusListIssuerId = noStatusListIssuerConfig.id;
    noStatusListIssuerRootZcap =
      `urn:zcap:root:${encodeURIComponent(noStatusListIssuerId)}`;
  });
  it('issues a VC-JWT VC 1.1 credential', async () => {
    const credential = structuredClone(mockCredential);
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${noStatusListIssuerId}/credentials/issue`,
        capability: noStatusListIssuerRootZcap,
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
    const expectedCredential = {
      ...credential,
      issuer: did,
      issuanceDate: payload.vc.issuanceDate ?? 'error: missing date'
    };
    payload.vc.should.deep.equal(expectedCredential);
  });
});

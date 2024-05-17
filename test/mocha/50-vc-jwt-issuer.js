/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {createRequire} from 'node:module';
import {httpClient} from '@digitalbazaar/http-client';
import {klona} from 'klona';
import {mockData} from './mock.data.js';
import {v4 as uuid} from 'uuid';

const require = createRequire(import.meta.url);

const {baseUrl} = mockData;
const serviceType = 'vc-issuer';

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');

describe('issue using VC-JWT format', () => {
  let assertionMethodKeyId;
  let capabilityAgent;
  let did;
  let keystoreAgent;
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
    ({capabilityAgent, keystoreAgent} = await helpers.provisionDependencies(
      {did, envelope, status: false}));

    // create EDV for storage (creating hmac and kak in the process)
    const {
      edvConfig,
      hmac,
      keyAgreementKey
    } = await helpers.createEdv({capabilityAgent, keystoreAgent});

    // get service agent to delegate to
    const serviceAgentUrl =
      `${baseUrl}/service-agents/${encodeURIComponent(serviceType)}`;
    const {data: serviceAgent} = await httpClient.get(serviceAgentUrl, {agent});

    // delegate edv, hmac, and key agreement key zcaps to service agent
    const zcaps = await helpers.delegateEdvZcaps({
      edvConfig, hmac, keyAgreementKey, serviceAgent,
      capabilityAgent
    });

    // delegate assertion method keys
    await helpers.delegateAssertionMethodZcaps({
      envelope, serviceAgent, capabilityAgent, zcaps
    });

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
  describe('/credentials/issue', () => {
    it('issues a VC-JWT VC 1.1 credential', async () => {
      const credential = klona(mockCredential);
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
      const header = JSON.parse(
        new TextDecoder().decode(base64url.decode(split[0])));
      const payload = JSON.parse(
        new TextDecoder().decode(base64url.decode(split[1])));
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
});

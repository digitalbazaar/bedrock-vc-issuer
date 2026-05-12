/*!
 * Copyright (c) 2020-2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as helpers from './helpers.js';

import {generateDeviceKeyPair, mdocContext} from './mdlUtils.js';
import {Holder, IssuerSigned} from '@owf/mdoc';

import {createRequire} from 'node:module';
import {generateCertificateChain} from './certUtils.js';
import {mockData} from './mock.data.js';
import {randomUUID as uuid} from 'node:crypto';

const require = createRequire(import.meta.url);

const mockVDL = require('./mock-vdl.json');

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const MDOC_TYPE_MDL = `${MDL_NAMESPACE}.mDL`;

describe('issue mDL', () => {
  let capabilityAgent;
  let did;
  let zcaps;
  let noStatusListIssuerId;
  let noStatusListIssuerRootZcap;
  let certificateEntities;
  let issuerCertificateChain;
  beforeEach(async () => {
    // use envelope-based security
    const envelope = {
      mediaType: 'application/mdl',
      algorithm: 'P-256'
    };

    // generate a `did:web` DID for the issuer
    const {host} = bedrock.config.server;
    const localId = uuid();
    did = `did:web:${encodeURIComponent(host)}:did-web:${localId}`;

    // provision dependencies
    ({capabilityAgent, zcaps} = await helpers.provisionDependencies(
      {did, envelope, status: false, zcaps: true}));

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
    let issuerKeyPair;
    let issuerPublicJwk;
    for(const {assertionMethodKey} of [envelope]) {
      const description = await assertionMethodKey.getKeyDescription();
      delete description['@context'];
      description.controller = did;
      didDocument.verificationMethod.push(description);
      didDocument.assertionMethod.push(description.id);
      issuerKeyPair = await EcdsaMultikey.from(description);
      issuerPublicJwk = await EcdsaMultikey.toJwk({keyPair: issuerKeyPair});
    }
    // add DID doc to map with DID docs to be served
    mockData.didWebDocuments.set(localId, didDocument);

    // create a certificate chain that ends in the MDL issuer (leaf)
    certificateEntities = await generateCertificateChain({
      leafKeyPairInfo: {
        keyPair: issuerKeyPair,
        jwk: issuerPublicJwk
      }
    });

    issuerCertificateChain = [certificateEntities.leaf.pemCertificate];

    // create issue options
    const issueOptions = {
      issuer: did,
      envelope: {
        mediaType: envelope.mediaType,
        options: {issuerCertificateChain},
        zcapReferenceIds: envelope.zcapReferenceIds
      }
    };

    // create issuer instance w/ no status list options
    const noStatusListIssuerConfig = await helpers.createIssuerConfig({
      capabilityAgent, zcaps, issueOptions
    });
    noStatusListIssuerId = noStatusListIssuerConfig.id;
    noStatusListIssuerRootZcap =
      `urn:zcap:root:${encodeURIComponent(noStatusListIssuerId)}`;
  });
  it('issues an mDL', async () => {
    // create device key pair for mDL
    const {publicJwk: devicePublicJwk} = await generateDeviceKeyPair();

    // issue mDL
    const credential = structuredClone(mockVDL);
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
            mdl: {devicePublicJwk}
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
    verifiableCredential.id.should.include('data:application/mdl;base64,');

    // assert mDL contents
    const b64 = verifiableCredential.id
      .slice('data:application/mdl;base64,'.length);
    const encodedIssuerSigned = Buffer.from(b64, 'base64');

    // decode issuerSigned directly — no CBOR container wrapping needed
    const issuerSigned = IssuerSigned.decode(encodedIssuerSigned);
    const rawFields = issuerSigned.getPrettyClaims(MDL_NAMESPACE);

    // @owf/mdoc decodes nested CBOR maps as JS Map instances; convert to
    // plain objects for comparison
    const fields = _deepMapToObject(rawFields);

    // issuer signed document should have matching fields from
    // credential subject's driver's license
    const expectedFields = {...credential.credentialSubject.driversLicense};
    delete expectedFields.type;

    should.exist(fields);
    issuerSigned.issuerAuth.mobileSecurityObject.docType.should.equal(
      MDOC_TYPE_MDL);
    fields.should.deep.equal(expectedFields);

    // verify issuer signature on mDL
    const trustedCertificates = [
      certificateEntities.intermediate.pemCertificate,
      certificateEntities.root.pemCertificate
    ].map(pem => new Uint8Array(Buffer.from(
      pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64')));

    await Holder.verifyIssuerSigned(
      {issuerSigned, trustedCertificates},
      mdocContext
    );
  });
});

function _deepMapToObject(value) {
  // handle native Map
  if(value instanceof Map) {
    const obj = {};
    for(const [k, v] of value) {
      obj[k] = _deepMapToObject(v);
    }
    return obj;
  }
  // handle @owf/mdoc's TypedMap, which wraps a native Map in a .map property
  if(value?.map instanceof Map) {
    const obj = {};
    for(const [k, v] of value.map) {
      obj[k] = _deepMapToObject(v);
    }
    return obj;
  }
  if(Array.isArray(value)) {
    return value.map(_deepMapToObject);
  }
  // recurse into plain objects so nested Maps are converted
  if(value !== null && typeof value === 'object') {
    const obj = {};
    for(const [k, v] of Object.entries(value)) {
      obj[k] = _deepMapToObject(v);
    }
    return obj;
  }
  return value;
}

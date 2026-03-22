/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import {randomUUID, webcrypto} from 'node:crypto';

const crypto = _createCrypto();

export async function generateCertificateChain({leafKeyPairInfo} = {}) {
  const root = await _createEntity({
    commonName: 'Root',
    serialNumber: 1
  });

  const intermediate = await _createEntity({
    issuer: root.subject,
    commonName: 'Intermediate',
    serialNumber: 2
  });

  const leaf = await _createEntity({
    issuer: intermediate.subject,
    commonName: 'Leaf',
    serialNumber: 3,
    keyPairInfo: leafKeyPairInfo
  });

  return {root, intermediate, leaf};
}

export async function generateKeyPair() {
  const algorithm = {
    algorithm: {name: 'ECDSA', namedCurve: 'P-256'},
    usages: ['sign', 'verify']
  };
  const keyPair = await crypto.subtle.generateKey(
    algorithm.algorithm, true, algorithm.usages);
  const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  jwk.kid = `urn:uuid:${randomUUID()}`;
  delete jwk.key_ops;
  delete jwk.ext;
  return {keyPair, jwk};
}

async function _createEntity({
  issuer, commonName, serialNumber, keyPairInfo
} = {}) {
  // generate subject key pair
  const {keyPair, jwk} = keyPairInfo ?? await generateKeyPair();

  // subject ID
  const subject = {
    commonName: commonName ?? 'Root',
    keyPair,
    jwk
  };

  if(!issuer) {
    // self-signed
    issuer = {...subject};
  }

  // create certificate
  const certificate = new pkijs.Certificate();
  certificate.version = 2;
  certificate.serialNumber = new asn1js.Integer({value: serialNumber});

  // issuer identity
  certificate.issuer.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    // common name
    type: '2.5.4.3',
    value: new asn1js.BmpString({value: issuer.commonName})
  }));
  certificate.issuer.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    // country name
    type: '2.5.4.6',
    value: new asn1js.PrintableString({value: 'US'})
  }));

  // subject identity
  certificate.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    // common name
    type: '2.5.4.3',
    value: new asn1js.BmpString({value: subject.commonName})
  }));
  certificate.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    // country name
    type: '2.5.4.6',
    value: new asn1js.PrintableString({value: 'US'})
  }));

  // validity period
  certificate.notBefore.value = new Date();
  const notAfter = new Date();
  notAfter.setUTCFullYear(notAfter.getUTCFullYear() + 1);
  certificate.notAfter.value = notAfter;

  // extensions are optional
  certificate.extensions = [];

  // `BasicConstraints` extension
  const basicConstr = new pkijs.BasicConstraints({
    cA: true,
    pathLenConstraint: 3
  });
  certificate.extensions.push(new pkijs.Extension({
    extnID: '2.5.29.19',
    critical: false,
    extnValue: basicConstr.toSchema().toBER(false),
    parsedValue: basicConstr // Parsed value for well-known extensions
  }));

  // `KeyUsage` extension
  const bitArray = new ArrayBuffer(1);
  const bitView = new Uint8Array(bitArray);
  // key usage `cRLSign` flag
  bitView[0] |= 0x02;
  // key usage `keyCertSign` flag
  bitView[0] |= 0x04;
  const keyUsage = new asn1js.BitString({valueHex: bitArray});
  certificate.extensions.push(new pkijs.Extension({
    extnID: '2.5.29.15',
    critical: false,
    extnValue: keyUsage.toBER(false),
    parsedValue: keyUsage // Parsed value for well-known extensions
  }));

  // export public key into `subjectPublicKeyInfo` value of certificate
  await certificate.subjectPublicKeyInfo.importKey(
    keyPair.publicKey, crypto);

  // sign certificate
  await certificate.sign(issuer.keyPair.privateKey, 'SHA-256', crypto);

  // export certificate to PEM
  const raw = certificate.toSchema().toBER();
  const pemCertificate = _toPem(raw);

  return {subject, issuer, certificate, pemCertificate};
}

function _createCrypto() {
  // initialize `pkijs` crypto engine only as needed
  try {
    pkijs.getEngine();
  } catch(e) {
    pkijs.setEngine('newEngine', new pkijs.CryptoEngine({
      name: 'newEngine', crypto: webcrypto, subtle: webcrypto.subtle
    }));
  }
  return pkijs.getCrypto(true);
}

function _toPem(buffer, tag = 'CERTIFICATE') {
  const wrapped = Buffer.from(buffer).toString('base64')
    .match(/.{1,76}/g).join('\n');
  return [
    `-----BEGIN ${tag}-----`,
    wrapped,
    `-----END ${tag}-----`,
    '',
  ].join('\n');
}

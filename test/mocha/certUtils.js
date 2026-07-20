/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc.
 */
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import {randomUUID, webcrypto} from 'node:crypto';

const crypto = _createCrypto();

export async function importJwk({jwk: inputJwk} = {}) {
  const algorithm = {
    algorithm: {name: 'ECDSA', namedCurve: 'P-256'},
    usages: ['verify']
  };
  if(inputJwk.d) {
    algorithm.usages.push('sign');
  }
  const cryptoKey = await crypto.subtle.importKey(
    'jwk', inputJwk, algorithm.algorithm, true, algorithm.usages);
  let keyPair;
  if(cryptoKey.privateKey) {
    keyPair = cryptoKey;
  } else {
    keyPair = {publicKey: cryptoKey};
  }
  const jwk = await crypto.subtle.exportKey(
    'jwk', keyPair.privateKey ?? keyPair.publicKey);
  jwk.kid = inputJwk.kid ?? `urn:uuid:${randomUUID()}`;
  delete jwk.key_ops;
  delete jwk.ext;
  return {keyPair, jwk};
}

export async function generateCertificateChain({leafConfig} = {}) {
  const root = await _createEntity({
    commonName: 'Root',
    cA: true,
    serialNumber: 1
  });

  const intermediate = await _createEntity({
    issuer: root.subject,
    commonName: 'Intermediate',
    cA: true,
    serialNumber: 2
  });

  const leaf = await _createEntity({
    issuer: intermediate.subject,
    commonName: leafConfig?.commonName ?? 'Leaf',
    dnsName: leafConfig?.dnsName ?? 'example.test',
    cA: leafConfig?.cA,
    serialNumber: 3,
    keyPairInfo: leafConfig?.keyPairInfo,
    privateKeyJwk: leafConfig?.privateKeyJwk,
    publicKeyJwk: leafConfig?.publicKeyJwk
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
  issuer, commonName, dnsName, cA = false, serialNumber,
  keyPairInfo, privateKeyJwk, publicKeyJwk
} = {}) {
  let keyPair;
  let jwk;
  if(keyPairInfo) {
    ({keyPair, jwk} = keyPairInfo);
  } else {
    // import or generate key pair
    const givenJwk = privateKeyJwk || publicKeyJwk;
    ({keyPair, jwk} = await (givenJwk ?
      importJwk({jwk: givenJwk}) : generateKeyPair()));
  }

  // subject ID
  const subject = {
    commonName: commonName ?? 'Root',
    dnsName,
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

  if(cA !== undefined) {
    // `BasicConstraints` extension
    const basicConstr = new pkijs.BasicConstraints({
      cA,
      pathLenConstraint: cA === true ? 3 : undefined
    });
    certificate.extensions.push(new pkijs.Extension({
      extnID: '2.5.29.19',
      critical: true,
      extnValue: basicConstr.toSchema().toBER(false),
      // Parsed value for well-known extensions
      parsedValue: basicConstr
    }));
  }

  // `KeyUsage` extension
  const bitArray = new ArrayBuffer(1);
  const bitView = new Uint8Array(bitArray);
  if(cA) {
    // key usage `cRLSign` flag
    bitView[0] |= 0x02;
    // key usage `keyCertSign` flag
    bitView[0] |= 0x04;
  }
  const keyUsage = new asn1js.BitString({valueHex: bitArray});
  certificate.extensions.push(new pkijs.Extension({
    extnID: '2.5.29.15',
    critical: true,
    extnValue: keyUsage.toBER(false),
    // Parsed value for well-known extensions
    parsedValue: keyUsage
  }));

  if(subject.dnsName) {
    // Subject Alternative Name
    const altNames = new pkijs.GeneralNames({
      names: [
        /*
        new pkijs.GeneralName({
          // email
          type: 1,
          value: "email@address.com"
        }),*/
        new pkijs.GeneralName({
          // domain
          type: 2,
          value: subject.dnsName
        })
      ]
    });

    certificate.extensions.push(new pkijs.Extension({
      // subject alt names
      // id-ce-subjectAltName
      extnID: '2.5.29.17',
      critical: false,
      extnValue: altNames.toSchema().toBER(false)
    }));
  }

  // export public key into `subjectPublicKeyInfo` value of certificate
  await certificate.subjectPublicKeyInfo.importKey(
    keyPair.publicKey, crypto);

  // sign certificate
  await certificate.sign(issuer.keyPair.privateKey, 'SHA-256', crypto);

  // export certificate to PEM
  const raw = certificate.toSchema().toBER();
  const pemCertificate = _toPem(raw);
  const b64Certificate = Buffer.from(raw).toString('base64');

  return {subject, issuer, certificate, pemCertificate, b64Certificate};
}

function _createCrypto() {
  // initialize `pkijs` crypto engine only as needed
  try {
    pkijs.getEngine();
  } catch {
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
    ''
  ].join('\n');
}

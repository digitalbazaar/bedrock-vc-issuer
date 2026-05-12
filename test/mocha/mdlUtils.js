/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as x509Lib from '@peculiar/x509';
import {exportJWK, importX509} from 'jose';
import {CoseKey} from '@owf/mdoc';
import {webcrypto} from 'node:crypto';

// mdocContext implements the crypto/cose/x509 interfaces required by @owf/mdoc
export const mdocContext = {
  crypto: {
    async digest({digestAlgorithm, bytes}) {
      const digest = await webcrypto.subtle.digest(
        digestAlgorithm, bytes);
      return new Uint8Array(digest);
    },
    random(length) {
      return webcrypto.getRandomValues(new Uint8Array(length));
    }
  },
  cose: {
    sign1: {
      async sign({key, toBeSigned}) {
        const cryptoKey = await webcrypto.subtle.importKey(
          'jwk', _cleanJwk(key.jwk),
          {name: 'ECDSA', namedCurve: 'P-256'},
          false, ['sign']);
        const sig = await webcrypto.subtle.sign(
          {name: 'ECDSA', hash: 'SHA-256'}, cryptoKey, toBeSigned);
        return new Uint8Array(sig);
      },
      async verify({sign1, key}) {
        const cryptoKey = await webcrypto.subtle.importKey(
          'jwk', _cleanJwk(key.jwk),
          {name: 'ECDSA', namedCurve: 'P-256'},
          false, ['verify']);
        return webcrypto.subtle.verify(
          {name: 'ECDSA', hash: 'SHA-256'}, cryptoKey,
          sign1.signature, sign1.toBeSigned);
      }
    }
  },
  x509: {
    getIssuerNameField({certificate, field}) {
      const cert = new x509Lib.X509Certificate(certificate);
      return cert.issuerName.getField(field);
    },
    async getPublicKey({certificate, alg}) {
      const cert = new x509Lib.X509Certificate(certificate);
      const key = await importX509(cert.toString(), alg, {extractable: true});
      return CoseKey.fromJwk(await exportJWK(key));
    },
    async verifyCertificateChain({trustedCertificates, x5chain, now}) {
      if(x5chain.length === 0) {
        throw new Error('Certificate chain is empty');
      }
      const leafCert = new x509Lib.X509Certificate(x5chain[0]);
      const mdocCerts = x5chain.map(c => new x509Lib.X509Certificate(c));
      const trustedCerts = trustedCertificates.map(
        c => new x509Lib.X509Certificate(c));
      const builder = new x509Lib.X509ChainBuilder({
        certificates: [...mdocCerts, ...trustedCerts]
      });
      const chain = await builder.build(leafCert);
      let parsedChain = chain.map(
        c => new x509Lib.X509Certificate(c.rawData)).reverse();
      if(parsedChain.length < x5chain.length) {
        throw new Error('Could not parse the full chain');
      }
      const trustedIdx = parsedChain.findIndex(
        cert => trustedCerts.some(t => cert.equal(t)));
      if(trustedIdx === -1) {
        throw new Error(
          'No trusted certificate was found while validating the X.509 chain');
      }
      parsedChain = parsedChain.slice(0, trustedIdx);
      for(let i = 0; i < parsedChain.length; i++) {
        const cert = parsedChain[i];
        const prev = parsedChain[i - 1];
        await cert.verify({
          publicKey: prev?.publicKey, date: now ?? new Date()
        });
      }
    },
    async getCertificateData({certificate}) {
      const cert = new x509Lib.X509Certificate(certificate);
      const thumbprint = await cert.getThumbprint(webcrypto);
      return {
        issuerName: cert.issuerName.toString(),
        subjectName: cert.subjectName.toString(),
        pem: cert.toString(),
        serialNumber: cert.serialNumber,
        thumbprint: Buffer.from(thumbprint).toString('hex'),
        notBefore: cert.notBefore,
        notAfter: cert.notAfter
      };
    }
  }
};

// strip undefined fields from a CoseKey JWK before passing to webcrypto
function _cleanJwk(jwk) {
  return Object.fromEntries(
    Object.entries(jwk).filter(([, v]) => v !== undefined));
}

export async function generateDeviceKeyPair() {
  // FIXME: generate new key pair each time
  const publicJwk = {
    kty: 'EC',
    x: 'QiUaYhZak1NubJEphQWmafykivrD80D2IpwqkkCU0oQ',
    y: 'sdNfR3813hzaUqF3-kWWOjI1xtSEqb93-graWFK-bA4',
    crv: 'P-256'
  };
  const privateJwk = {
    ...publicJwk,
    d: 'V729tbSdAGAL34Gqt2lGFM0Y9qrxILDUVheFduEkgFU'
  };
  return {publicJwk, privateJwk};
}


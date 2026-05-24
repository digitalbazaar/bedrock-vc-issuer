/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {exportJWK, importX509} from 'jose';
import {webcrypto, X509Certificate} from 'node:crypto';
import {CoseKey} from '@owf/mdoc';

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
      const cert = new X509Certificate(certificate);
      return _parseDN(cert.issuer)[field] ?? [];
    },
    async getPublicKey({certificate, alg}) {
      const cert = new X509Certificate(certificate);
      const key = await importX509(cert.toString(), alg, {extractable: true});
      return CoseKey.fromJwk(await exportJWK(key));
    },
    async verifyCertificateChain({trustedCertificates, x5chain, now}) {
      if(x5chain.length === 0) {
        throw new Error('Certificate chain is empty');
      }
      const chain = x5chain.map(c => new X509Certificate(c));
      const trusted = trustedCertificates.map(c => new X509Certificate(c));

      // verify each cert in the chain is issued by the next
      for(let i = 0; i < chain.length - 1; i++) {
        const cert = chain[i];
        const issuer = chain[i + 1];
        if(!cert.checkIssued(issuer)) {
          throw new Error(
            `Certificate at index ${i} was not issued by ` +
            `certificate at index ${i + 1}`);
        }
        if(!cert.verify(issuer.publicKey)) {
          throw new Error(
            `Certificate at index ${i} failed signature verification`);
        }
        _checkValidity(cert, now);
      }

      // the last cert in the chain must be trusted (or self-signed by trusted)
      const lastCert = chain[chain.length - 1];
      const isTrusted = trusted.some(t => {
        try {
          return lastCert.verify(t.publicKey) && lastCert.checkIssued(t);
        } catch {
          return false;
        }
      });
      if(!isTrusted) {
        throw new Error(
          'No trusted certificate was found while validating the X.509 chain');
      }
      _checkValidity(lastCert, now);
    },
    async getCertificateData({certificate}) {
      const cert = new X509Certificate(certificate);
      // fingerprint256 is "XX:XX:..." — strip colons for a hex thumbprint
      const thumbprint = cert.fingerprint256.replace(/:/g, '').toLowerCase();
      return {
        issuerName: cert.issuer,
        subjectName: cert.subject,
        pem: cert.toString(),
        serialNumber: cert.serialNumber,
        thumbprint,
        notBefore: new Date(cert.validFrom),
        notAfter: new Date(cert.validTo)
      };
    }
  }
};

// parse a distinguished name string into a field map; handles both
// " + " (Node.js multi-valued RDN format) and "\n" separators
function _parseDN(dn) {
  const fields = {};
  for(const part of dn.split(/\s*\+\s*|\n/)) {
    const idx = part.indexOf('=');
    if(idx === -1) {
      continue;
    }
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if(!fields[key]) {
      fields[key] = [];
    }
    fields[key].push(val);
  }
  return fields;
}

// check certificate validity window; throw if outside [notBefore, notAfter]
function _checkValidity(cert, now) {
  const date = now ?? new Date();
  const notBefore = new Date(cert.validFrom);
  const notAfter = new Date(cert.validTo);
  if(date < notBefore || date > notAfter) {
    throw new Error(
      `Certificate is not valid at ${date.toUTCString()} ` +
      `(valid ${notBefore.toUTCString()} to ${notAfter.toUTCString()})`);
  }
}

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

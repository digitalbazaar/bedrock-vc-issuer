/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {
  CoseKey, DeviceKey, Holder, Issuer, SignatureAlgorithm
} from '@owf/mdoc';
import {generateCertificateChain, generateKeyPair} from './certUtils.js';
import {mdocContext} from './mdlUtils.js';

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const MDOC_TYPE_MDL = `${MDL_NAMESPACE}.mDL`;

const DEVICE_PUBLIC_JWK = {
  kty: 'EC', crv: 'P-256',
  x: 'QiUaYhZak1NubJEphQWmafykivrD80D2IpwqkkCU0oQ',
  y: 'sdNfR3813hzaUqF3-kWWOjI1xtSEqb93-graWFK-bA4'
};

function _toDer(pem) {
  return new Uint8Array(Buffer.from(
    pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64'));
}

function _validityInfo() {
  const signed = new Date();
  const validFrom = new Date(signed);
  const validUntil = new Date(signed);
  validUntil.setFullYear(validUntil.getFullYear() + 1);
  return {signed, validFrom, validUntil};
}

async function _sign({jwk, issuerCertDer, claims}) {
  const issuer = new Issuer(MDOC_TYPE_MDL, mdocContext);
  issuer.addIssuerNamespace(MDL_NAMESPACE, claims);
  return issuer.sign({
    signingKey: CoseKey.fromJwk(jwk),
    certificates: [issuerCertDer],
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: {deviceKey: DeviceKey.fromJwk(DEVICE_PUBLIC_JWK)},
    validityInfo: _validityInfo()
  });
}

describe('mdocContext', () => {
  it('issue(): signs an mDL with mdocContext', async () => {
    const {keyPair, jwk} = await generateKeyPair();
    const {leaf} = await generateCertificateChain({
      leafKeyPairInfo: {keyPair, jwk}
    });

    const issuerSigned = await _sign({
      jwk,
      issuerCertDer: _toDer(leaf.pemCertificate),
      claims: {family_name: 'Test', given_name: 'User'}
    });

    should.exist(issuerSigned, 'issuerSigned should be returned');
    const claims = issuerSigned.getPrettyClaims(MDL_NAMESPACE);
    claims.family_name.should.equal('Test');
    claims.given_name.should.equal('User');
  });

  it('Holder.verifyIssuerSigned(): verifies a signed mDL', async () => {
    const {keyPair, jwk} = await generateKeyPair();
    const {leaf, intermediate, root} = await generateCertificateChain({
      leafKeyPairInfo: {keyPair, jwk}
    });

    const trustedCertificates = [
      _toDer(intermediate.pemCertificate),
      _toDer(root.pemCertificate)
    ];

    const issuerSigned = await _sign({
      jwk,
      issuerCertDer: _toDer(leaf.pemCertificate),
      claims: {family_name: 'Test'}
    });

    // should not throw
    await Holder.verifyIssuerSigned(
      {issuerSigned, trustedCertificates}, mdocContext);
  });

  it('verifyIssuerSigned(): rejects untrusted certificate', async () => {
    const {keyPair, jwk} = await generateKeyPair();
    const {leaf} = await generateCertificateChain({
      leafKeyPairInfo: {keyPair, jwk}
    });

    // use a different chain as trusted — should fail verification
    const {root: untrustedRoot} = await generateCertificateChain();
    const wrongTrustedCerts = [_toDer(untrustedRoot.pemCertificate)];

    const issuerSigned = await _sign({
      jwk,
      issuerCertDer: _toDer(leaf.pemCertificate),
      claims: {family_name: 'Test'}
    });

    let err;
    try {
      await Holder.verifyIssuerSigned(
        {issuerSigned, trustedCertificates: wrongTrustedCerts}, mdocContext);
    } catch(e) {
      err = e;
    }
    should.exist(err, 'verification should fail with untrusted certificate');
  });
});

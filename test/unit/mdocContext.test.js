/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc. All rights reserved.
 *
 * Standalone unit test for mdocContext — runs without the Bedrock stack.
 * Execute with: node --experimental-vm-modules test/unit/mdocContext.test.js
 */
import {
  CoseKey, DeviceKey, Holder, Issuer, SignatureAlgorithm
} from '@owf/mdoc';
import {generateCertificateChain, generateKeyPair} from '../mocha/certUtils.js';
import {mdocContext} from '../mocha/mdlUtils.js';

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const MDOC_TYPE_MDL = `${MDL_NAMESPACE}.mDL`;

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch(e) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${e.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if(!condition) {
    throw new Error(message ?? 'Assertion failed');
  }
}

function _validityInfo() {
  const signed = new Date();
  const validFrom = new Date(signed);
  const validUntil = new Date(signed);
  validUntil.setFullYear(validUntil.getFullYear() + 1);
  return {signed, validFrom, validUntil};
}

console.log('\nmdocContext unit tests\n');

// issue and verify a real IssuerSigned using mdocContext
await test('issue(): signs an mDL with mdocContext', async () => {
  const {keyPair, jwk} = await generateKeyPair();
  const {leaf} = await generateCertificateChain({
    leafKeyPairInfo: {keyPair, jwk}
  });

  const toDer = pem => new Uint8Array(Buffer.from(
    pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64'));

  const devicePublicJwk = {
    kty: 'EC', crv: 'P-256',
    x: 'QiUaYhZak1NubJEphQWmafykivrD80D2IpwqkkCU0oQ',
    y: 'sdNfR3813hzaUqF3-kWWOjI1xtSEqb93-graWFK-bA4'
  };

  const issuer = new Issuer(MDOC_TYPE_MDL, mdocContext);
  issuer.addIssuerNamespace(MDL_NAMESPACE, {
    family_name: 'Test',
    given_name: 'User'
  });
  const issuerSigned = await issuer.sign({
    signingKey: CoseKey.fromJwk(jwk),
    certificates: [toDer(leaf.pemCertificate)],
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: {deviceKey: DeviceKey.fromJwk(devicePublicJwk)},
    validityInfo: _validityInfo()
  });

  assert(issuerSigned, 'issuerSigned should be returned');
  const claims = issuerSigned.getPrettyClaims(MDL_NAMESPACE);
  assert(claims.family_name === 'Test', 'family_name should match');
  assert(claims.given_name === 'User', 'given_name should match');
});

await test('Holder.verifyIssuerSigned(): verifies a signed mDL', async () => {
  const {keyPair, jwk} = await generateKeyPair();
  const {leaf, intermediate, root} = await generateCertificateChain({
    leafKeyPairInfo: {keyPair, jwk}
  });

  const toDer = pem => new Uint8Array(Buffer.from(
    pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64'));

  const issuerCertDer = toDer(leaf.pemCertificate);
  const trustedCertificates = [
    toDer(intermediate.pemCertificate),
    toDer(root.pemCertificate)
  ];

  const devicePublicJwk = {
    kty: 'EC', crv: 'P-256',
    x: 'QiUaYhZak1NubJEphQWmafykivrD80D2IpwqkkCU0oQ',
    y: 'sdNfR3813hzaUqF3-kWWOjI1xtSEqb93-graWFK-bA4'
  };

  const issuer = new Issuer(MDOC_TYPE_MDL, mdocContext);
  issuer.addIssuerNamespace(MDL_NAMESPACE, {family_name: 'Test'});
  const issuerSigned = await issuer.sign({
    signingKey: CoseKey.fromJwk(jwk),
    certificates: [issuerCertDer],
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: {deviceKey: DeviceKey.fromJwk(devicePublicJwk)},
    validityInfo: _validityInfo()
  });

  // should not throw
  await Holder.verifyIssuerSigned(
    {issuerSigned, trustedCertificates}, mdocContext);
});

await test('verifyIssuerSigned(): rejects untrusted certificate', async () => {
  const {keyPair, jwk} = await generateKeyPair();
  const {leaf} = await generateCertificateChain({
    leafKeyPairInfo: {keyPair, jwk}
  });

  // use a different chain as trusted — should fail verification
  const {root: untrustedRoot} = await generateCertificateChain();
  const toDer = pem => new Uint8Array(Buffer.from(
    pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64'));

  const issuerCertDer = toDer(leaf.pemCertificate);
  const wrongTrustedCerts = [toDer(untrustedRoot.pemCertificate)];

  const devicePublicJwk = {
    kty: 'EC', crv: 'P-256',
    x: 'QiUaYhZak1NubJEphQWmafykivrD80D2IpwqkkCU0oQ',
    y: 'sdNfR3813hzaUqF3-kWWOjI1xtSEqb93-graWFK-bA4'
  };

  const issuer = new Issuer(MDOC_TYPE_MDL, mdocContext);
  issuer.addIssuerNamespace(MDL_NAMESPACE, {family_name: 'Test'});
  const issuerSigned = await issuer.sign({
    signingKey: CoseKey.fromJwk(jwk),
    certificates: [issuerCertDer],
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: {deviceKey: DeviceKey.fromJwk(devicePublicJwk)},
    validityInfo: _validityInfo()
  });

  let threw = false;
  try {
    await Holder.verifyIssuerSigned(
      {issuerSigned, trustedCertificates: wrongTrustedCerts}, mdocContext);
  } catch {
    threw = true;
  }
  assert(threw, 'verification should fail with untrusted certificate');
});

console.log(`\n${passed} passed, ${failed} failed\n`);
if(failed > 0) {
  process.exit(1);
}

/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';

const TEXT_ENCODER = new TextEncoder();
const ENCODED_PERIOD = TEXT_ENCODER.encode('.');

// produce VC-JWT-enveloped VC
export async function envelopeCredential({
  verifiableCredential, signer, options = {}
} = {}) {
  /* Example:
  {
    "alg": <signer.algorithm>,
    "kid": <signer.id>
  }.
  {
    "iss": <verifiableCredential.issuer>,
    "jti": <verifiableCredential.id>
    "sub": <verifiableCredential.credentialSubject>
    "nbf": <verifiableCredential.[issuanceDate | validFrom]>
    "exp": <verifiableCredential.[expirationDate | validUntil]>
    "vc": <verifiableCredential>
  }
  */
  const {
    id, issuer, credentialSubject,
    issuanceDate, expirationDate, validFrom, validUntil
  } = verifiableCredential;

  const payload = {
    iss: issuer?.id ?? issuer
  };

  if(id !== undefined) {
    payload.jti = id;
  }

  // use `id` property of (first) credential subject
  let sub = Array.isArray(credentialSubject) ?
    credentialSubject[0] : credentialSubject;
  sub = sub?.id ?? sub;
  if(typeof sub === 'string') {
    payload.sub = sub;
  }

  let nbf = issuanceDate ?? validFrom;
  if(nbf !== undefined) {
    nbf = Date.parse(nbf);
    if(!isNaN(nbf)) {
      payload.nbf = Math.floor(nbf / 1000);
    }
  }

  let exp = expirationDate ?? validUntil;
  if(exp !== undefined) {
    exp = Date.parse(exp);
    if(!isNaN(exp)) {
      payload.exp = Math.floor(exp / 1000);
    }
  }

  payload.vc = verifiableCredential;

  const {id: kid} = signer;
  const alg = options.alg ?? _curveToAlg(signer.algorithm);
  const protectedHeader = {alg, kid};

  return signJWT({payload, protectedHeader, signer});
}

export async function signJWT({payload, protectedHeader, signer} = {}) {
  // encode payload and protected header
  const b64Payload = base64url.encode(JSON.stringify(payload));
  const b64ProtectedHeader = base64url.encode(JSON.stringify(protectedHeader));
  payload = TEXT_ENCODER.encode(b64Payload);
  protectedHeader = TEXT_ENCODER.encode(b64ProtectedHeader);

  // concatenate
  const data = new Uint8Array(
    protectedHeader.length + ENCODED_PERIOD.length + payload.length);
  data.set(protectedHeader);
  data.set(ENCODED_PERIOD, protectedHeader.length);
  data.set(payload, protectedHeader.length + ENCODED_PERIOD.length);

  // sign
  const signature = await signer.sign({data});

  // create JWS
  const jws = {
    signature: base64url.encode(signature),
    payload: b64Payload,
    protected: b64ProtectedHeader
  };

  // create compact JWT
  return `${jws.protected}.${jws.payload}.${jws.signature}`;
}

function _curveToAlg(crv) {
  if(crv === 'Ed25519' || crv === 'Ed448') {
    return 'EdDSA';
  }
  if(crv?.startsWith('P-')) {
    return `ES${crv.slice(2)}`;
  }
  if(crv === 'secp256k1') {
    return 'ES256K';
  }
  return crv;
}

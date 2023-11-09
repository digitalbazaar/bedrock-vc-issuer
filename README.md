# Bedrock Verifiable Credentials Issuer API module _(bedrock-vc-issuer)_

[![Build Status](https://img.shields.io/github/actions/workflow/status/digitalbazaar/bedrock-vc-issuer/main.yml)](https://github.com/digitalbazaar/bedrock-vc-issuer/actions?query=workflow%3A%22Bedrock+Node.js+CI%22)
[![NPM Version](https://img.shields.io/npm/v/bedrock-vc-issuer.svg)](https://npm.im/bedrock-vc-issuer)

> A VC Issuer API library for use with Bedrock applications.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

* [Verifiable Credentials HTTP API v0.3](https://w3c-ccg.github.io/vc-api/) specification.
* Supports `RevocationList2020Status` type.

## Security

TBD

## Install

- Node.js 18+ is required.

### NPM

To install via NPM:

```
npm install --save @bedrock/vc-issuer
```

### Development

To install locally (for development):

```
git clone https://github.com/digitalbazaar/bedrock-vc-issuer.git
cd bedrock-vc-issuer
npm install
```

## Usage

In `lib/index.js`:

```js
import '@bedrock/vc-issuer';
```

Note: The use of [`bedrock-web-vc-issuer`](https://github.com/digitalbazaar/bedrock-web-vc-issuer) client is recommended,
to create instances.

### Issuer HTTP API

This module exposes the following API endpoints.

#### DID Authentication - `POST /vc-issuer/authenticate`

Example request:

```json
{
  "presentation": {
    "type": "VerifiablePresentation",
    "holder": "<account controller's DID>",
    "proof": {
      "challenge": "<challenge is required>",
      "type": "...",
      "proofPurpose": "authentication",
      "created": "...",
      "verificationMethod": "<key id>",
      "proofValue": "..."
    }
  }
}
```

#### Issue a Credential - `POST /vc-issuer/issue`
`Authorization` header is required.

Example request:

```json
{
  "credential": {
  }
}
```

Example response:

```json
{
  "verifiableCredential": {
  }
}
```

#### Instance Issue Credential - `POST /credentials/:profileAgentId/issueCredential`

Example request:

```json
{
  "credential": {
  },
  "options": {
    "proofPurpose": "assertionMethod",
    "assertionMethod": "<key id>",
    "verificationMethod": "<key id>",
    "credentialStatus": {
      "type": "RevocationList2020Status"
    }
  }
}
```

#### Update Credential Status - `POST /credentials/:profileAgentId/updateCredentialStatus`

Example request:

```json
{
  "credentialId": "...",
  "credentialStatus": {
    "type": "RevocationList2020Status"
  }
}
```

```
HTTP 200 OK
```

#### Publish RLC - `POST /vc-issuer/instances/:instanceId/rlc/:rlcId/publish`
Uses either `bedrock-passport` authentication, or an `Authorization` header bearer token.

Example request:

```json
{
  "profileAgent": {
  }
}
```

Example response:

```
HTTP 204 No Content
```

#### Get RLC - `GET /vc-issuer/instances/:instanceId/rlc/:rlcId`

No authz required.

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[Bedrock Non-Commercial License v1.0](LICENSE.md) © Digital Bazaar

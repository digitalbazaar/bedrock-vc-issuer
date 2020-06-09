# bedrock-vc-issuer ChangeLog

## 4.0.0 -

### Changed
  - **BREAKING**: Use bedrock-mongodb ^7.0.0.
  - Add a working test for the issuer.
  - Update mongodb calls to use mongo driver 3.5 api

## 3.1.0 - 2020-05-18

### Changed
- Add support for `did:v1` resolution.

## 3.0.0 - 2020-04-09

### Changed
- **BREAKING**: Obsolete APIs have been removed. See git history for changes.

## 2.0.0 - 2020-04-07

### Changed
- **BREAKING**: Signs a VC using capabilities and keys delegated from a wallet
  profile.
- **BREAKING**: The automated issuer endpoint requires an application token
  to be provided in the "authorization" header.
- **BREAKING**: The automated issuer endpoint now accepts a single credential
  to be issued.

## 1.0.0 - 2020-02-27

### Added
- Added core files.
- See git history for changes.

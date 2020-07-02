# bedrock-vc-issuer ChangeLog

## 5.2.0 - 2020-07-01

### Changed
- Update deps.
- Update test deps.

## 5.1.0 - 2020-06-30

### Changed
- Update peerDependencies to include bedrock-account@4.
- Update test deps.
- Update CI workflow.
- Improve test coverage.

## 5.0.0 - 2020-06-24

### Changed
- **BREAKING**: Use edv-client@4. This is a breaking change here because of
  changes in how edv-client serializes documents.

## 4.0.0 - 2020-06-09

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

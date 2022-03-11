# bedrock-vc-issuer ChangeLog

## 10.0.0 - 2022-03-xx

### Changed
- **BREAKING**: Update peer dependencies:
  - `bedrock-service-core@3`
  - `bedrock-service-context-store@3`
  - `bedrock-did-io@6.1`.

## 9.0.1 - 2022-03-10

### Fixed
- Fix linting error.

## 9.0.0 - 2022-03-10

### Changed
- **BREAKING**: Disable loading contexts from the Web by default.

### Removed
- **BREAKING**: Remove side-tracking of credential statuses in VC EDV
  document meta data. This side-tracking can get out of sync with the
  status list and it is an unnecessary complexity.

## 8.0.0 - 2022-03-01

### Changed
- **BREAKING**: Move zcap revocations to `/zcaps/revocations` to better
  future proof.
- **BREAKING**: Require `bedrock-service-core@2`, `bedrock-service-agent@2`,
  and `bedrock-service-context-store@2` peer dependencies.

### Removed
- Remove unused `@digitalbazaar/http-client` dependency.

## 7.1.0 - 2022-02-23

### Added
- Add default (dev mode) `app-identity` entry for `vc-issuer` service.

## 7.0.1 - 2022-02-21

### Changed
- Use `@digitalbazaar/vc-status-list-context` and updated bedrock-vc-status-list-context.
  These dependencies have no changes other than moved package locations.

## 7.0.0 - 2022-02-20

### Changed
- **BREAKING**: Complete refactor to run on top of `bedrock-service*` modules. While
  this version has similar functionality, its APIs and implementation are a clean
  break from previous versions.

## 6.0.1 - 2021-08-30

### Fixed
- Revert back to appending the revocation list context to the credential.

## 6.0.0 - 2021-08-30

### Changed
- **BREAKING**: Update to use latest Ed25519 key and signature suites, latest `did-io`.

## 5.4.0 - 2021-01-12

### Changed
- Update bedrock-account@5.0.

## 5.3.0 - 2020-12-17

### Changed
- Update deps.
- Update test deps.
- Update peerDependencies.
- Use bitstring from @digitalbazaar/bitstring.

### Fixed
- Include privateKmsBaseUrl and publicKmsBaseUrl in test.
- Add keyResolver in test.

## 5.2.1 - 2020-07-07

### Fixed
- Fix usage of the MongoDB projection API.

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

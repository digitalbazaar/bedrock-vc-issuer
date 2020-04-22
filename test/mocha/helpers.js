const sinon = require('sinon');
const bedrock = require('bedrock');
const brPassport = require('bedrock-passport');
const edvStorage = require('bedrock-edv-storage');
const edvHelpers = require('bedrock-edv-storage/lib/helpers');
const {profiles, profileAgents} = require('bedrock-profile');
const {
  AsymmetricKey,
  CapabilityAgent,
  KeystoreAgent,
  KeyAgreementKey,
  Hmac,
  KmsClient
} = require('webkms-client');
const {config, util: {uuid}} = bedrock;

const {kmsModule, server: {baseUri}} = config;

async function insertIssuerAgent({id, token}) {
  // this is the profile associated with an issuer account
  const {id: profileId} = await profiles.create({accountId: id});
  const profileAgentRecord = await profileAgents.getByProfile(
    {profileId, accountId: id, includeSecrets: true});
  const {profileAgent, secrets} = profileAgentRecord;
  // we will need this to delegate and invoke
  const invocationSigner = await profileAgents.getSigner({profileAgentRecord});
  const {capabilityAgent, keystoreAgent} = await profileAgents.getAgents(
    {profileAgent, secrets});
  // creates an edv for the profile-agent-edv-document
  const profileAgentEdvDocument = 'profile-agent-edv-document';
  // this is the userProfileEdv usually created in the wallet.
  const {edvId, hmac, keyAgreementKey} = await createProfileEdv({
    profileId,
    referenceId: profileAgentEdvDocument,
    keystoreAgent
  });
  const profileContent = {
    name: 'test-user',
    type: ['User', 'Person']
  }
  const result = await initializeAccessManagement({
    edvId,
    profileId,
    profileContent,
    hmac,
    keyAgreementKey
  });
  // now that we have an edv for the test
  // we need to delegate read only access to us.
  const delegateEdvDocumentRequest = {
    referenceId: profileAgentEdvDocument,
    // the profile agent is only allowed to read its own doc
    allowedAction: ['read'],
    controller: profileId,
    parentCapability: `${edvId}/zcaps/documents`
  };

  // this is the profileAgent created for an issuer instance integration
  // this is the profileAgent used to issue a credential.
  const integration = await profileAgents.create({profileId, token});
  return {instance: {id: profileId}, integration};
}

async function createProfileEdv({profileId, referenceId, keystoreAgent}) {
  const [keyAgreementKey, hmac] = await Promise.all([
    keystoreAgent.generateKey({
      type: 'keyAgreement',
      kmsModule
    }),
    keystoreAgent.generateKey({
      type: 'hmac',
      kmsModule
    })
  ]);
  const edvId = `${baseUri}/edvs/${(await edvHelpers.generateRandom())}`;
  const config = {
    id: edvId,
    sequence: 0,
    controller: profileId,
    referenceId,
    keyAgreementKey: {id: keyAgreementKey.id, type: keyAgreementKey.type},
    hmac: {id: hmac.id, type: hmac.type}
  };
  const result = await edvStorage.insertConfig({actor: null, config});
  return {keyAgreementKey, hmac, config: result, edvId};
}

// this will create the user edv and store
// the necessary zcaps in it used by the instance's issuer
async function initializeAccessManagement({
  profileId,
  profileContent,
  profileAgentContext = {},
  edvId,
  hmac,
  keyAgreementKey,
  indexes: []
}) {
  // create access management info
  const accessManagement = {
    hmac: {id: hmac.id, type: hmac.type},
    keyAgreementKey: {id: keyAgreementKey.id, type: keyAgreementKey.type},
    indexes: [
      {attribute: 'content.id', unique: true},
      {attribute: 'content.type'},
      ...indexes
    ],
    zcaps: {}
  };
}

exports.insertIssuerAgent = insertIssuerAgent;

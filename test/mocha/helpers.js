const sinon = require('sinon');
const bedrock = require('bedrock');
const brPassport = require('bedrock-passport');
const edvStorage = require('bedrock-edv-storage');
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

async function insertIssuerAgent({id, token}) {
  // this is the profile associated with an issuer account
  const {id: profileId} = await profiles.create({accountId: id});
  const profileAgentRecord = await profileAgents.getByProfile(
    {profileId, accountId: id, includeSecrets: true})
  const {profileAgent, secrets} = profileAgentRecord;
  const {profileCapabilityInvocationKey} = profileAgent.zcaps;
  const invocationSigner = await profileAgents.getSigner({profileAgentRecord});
  const {capabilityAgent, keystoreAgent} = await profileAgents.getAgents(
    {profileAgent, secrets});
  const [keyAgreementKey, hmac] = await Promise.all([
    keystoreAgent.generateKey({
      type: 'keyAgreement',
      kmsModule: config.kmsModule,
    }),
    keystoreAgent.generateKey({
      type: 'hmac',
      kmsModule: config.kmsModule,
    })
  ]);
console.log('profile\'s profileAgent', keyAgreementKey, hmac);
  // this is the userProfileEdv usually created in the wallet.
/**
  const config = {
    id: `urn:uuid:${uuid()}`,
    sequence: 0,
    controller: profileId,
    referenceId: 'vc-issuer-test-user',
    keyAgreementKey: {id: keyAgreementKey.id, type: keyAgreementKey.type},
    hmac: {id: hmac.id, type: hmac.type}
  };

  const delegateEdvDocumentRequest = {
    referenceId: `profile-agent-edv-document`,
    // the profile agent is only allowed to read its own doc
    allowedAction: ['read'],
    controller: profileId,
    parentCapability: `${edvId}/zcaps/documents`
  };
*/
  // this is the profileAgent created for an issuer instance integration
  // this is the profileAgent used to issue a credential.
  const integration = await profileAgents.create({profileId, token});
  return {instance: {id: profileId}, integration};
}

exports.stubPassport = ({actor}) => {
  const passportStub = sinon.stub(brPassport, 'optionallyAuthenticated');
  passportStub.callsFake((req, res, next) => {
    req.user = {
      account: {},
      actor,
    };
    next();
  });
  return passportStub;
};

exports.insertIssuerAgent = insertIssuerAgent;

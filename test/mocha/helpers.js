const axios = require('axios');
const bedrock = require('bedrock');
const {CapabilityDelegation} = require('ocapld');
const {httpsAgent} = require('bedrock-https-agent');
const edvStorage = require('bedrock-edv-storage');
const edvHelpers = require('bedrock-edv-storage/lib/helpers');
const {profiles, profileAgents} = require('bedrock-profile');
const {EdvClient, EdvDocument} = require('edv-client');
const jsigs = require('jsonld-signatures');
const {AsymmetricKey} = require('webkms-client');

const {config, util: {uuid}} = bedrock;
const {SECURITY_CONTEXT_V2_URL, sign, suites} = jsigs;
const {Ed25519Signature2018} = suites;

const {kmsModule, server: {baseUri}} = config;
const JWE_ALG = 'ECDH-ES+A256KW';
const profileAgentEdvDocument = 'profile-agent-edv-document';

async function keyResolver({id}) {
  const headers = {Accept: 'application/ld+json, application/json'};
  const response = await axios.get(id, {headers, httpsAgent});
  return response.data;
}

function stubPassport(passportStub) {
  passportStub.callsFake((req, res, next) => {
    req.user = {
      account: {},
      actor: {
        id: 'theMockControllerId'
      }
    };
    next();
  });
}

async function delegateCapability({signer, request}) {
  const zcap = {
    '@context': SECURITY_CONTEXT_V2_URL,
    id: `urn:zcap:${await edvHelpers.generateRandom()}`,
    ...request
  };
  const verificationMethod = signer.id;
  const capabilityChain = [zcap.parentCapability];
  return sign(zcap, {
    suite: new Ed25519Signature2018({signer, verificationMethod}),
    purpose: new CapabilityDelegation({capabilityChain}),
    compactProof: false
  });
}

async function insertIssuerAgent({id, token}) {
  // this is the profile associated with an issuer account
  const {id: profileId} = await profiles.create({accountId: id});
  const profileAgentRecord = await profileAgents.getByProfile(
    {profileId, accountId: id, includeSecrets: true});
  const {profileAgent, secrets} = profileAgentRecord;
  // we will need this to delegate and invoke
  const {capabilityAgent, keystoreAgent} = await profileAgents.getAgents(
    {profileAgent, secrets});
  const agentSigner = await profileAgents.getSigner({profileAgentRecord});
  const {profileCapabilityInvocationKey} = profileAgent.zcaps;
  // the profile signer is authorized to sign with the profileAgent's key?
  const profileSigner = new AsymmetricKey({
    capability: profileCapabilityInvocationKey,
    invocationSigner: agentSigner,
    kmsClient: keystoreAgent.kmsClient
  });
  // creates an edv for the profile-agent-edv-document
  // this is the userProfileEdv usually created in the wallet.
  const {edvId, hmac, keyAgreementKey} = await createProfileEdv({
    profileId,
    referenceId: profileAgentEdvDocument,
    keystoreAgent
  });
  const profileContent = {
    name: 'test-user',
    type: ['User', 'Person']
  };
  const result = await initializeAccessManagement({
    edvId,
    profileId,
    profileContent,
    hmac,
    keyAgreementKey,
    invocationSigner: profileSigner,
    profileAgentRecord
  });

  // this is the profileAgent created for an issuer instance integration
  // it is used to issue a credential.
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
  indexes = [],
  invocationSigner,
  profileAgentRecord
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
  const profileZcaps = {...profileContent.zcaps};
  const capability = `${edvId}/zcaps/documents`;
  accessManagement.edvId = edvId;
  // TODO this can be accomplished with back end only code
  const client = new EdvClient(
    {id: edvId, keyResolver, httpsAgent, keyAgreementKey, hmac});
  for(const index of accessManagement.indexes) {
    client.ensureIndex(index);
  }
  const recipients = [{
    header: {kid: keyAgreementKey.id, alg: JWE_ALG}
  }];
  const profileDocId = await edvHelpers.generateRandom();
  // TODO this can be accomplished with back end only code
  const profileUserDoc = new EdvDocument({
    id: profileDocId, recipients, keyResolver, keyAgreementKey, hmac,
    capability, invocationSigner, client
  });
  const type = ['User', 'Profile'];
  const profile = {
    ...profileContent,
    id: profileId,
    type,
    accessManagement,
    zcaps: profileZcaps
  };
  await profileUserDoc.write({
    doc: {
      id: profileDocId,
      content: profile
    }
  });
  const documentsUrl = `${edvId}/documents`;
  // now that we have an edv for the test
  // we need to delegate read only access to us.
  const delegateUserEdvDocumentRequest = {
    referenceId: profileAgentEdvDocument,
    // the profile agent is only allowed to read its own doc
    allowedAction: ['read'],
    controller: profileId,
    parentCapability: capability,
    invocationTarget: {
      id: `${documentsUrl}/${profileDocId}`,
      type: 'urn:edv:document'
    }
  };
}

exports.insertIssuerAgent = insertIssuerAgent;
exports.stubPassport = stubPassport;

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

async function getSigners({profileAgentRecord, keystoreAgent}) {
  const {profileAgent} = profileAgentRecord;
  const {profileCapabilityInvocationKey} = profileAgent.zcaps;
  const agentSigner = await profileAgents.getSigner({profileAgentRecord});
  const profileSigner = new AsymmetricKey({
    capability: profileCapabilityInvocationKey,
    invocationSigner: agentSigner,
    kmsClient: keystoreAgent.kmsClient
  });
  return {agentSigner, profileSigner};
}

async function insertIssuerAgent({id, token}) {
  // this is the profile associated with an issuer account
  const {id: profileId} = await profiles.create({accountId: id});
  const profileAgentRecord = await profileAgents.getByProfile(
    {profileId, accountId: id, includeSecrets: true});
  const {profileAgent, secrets} = profileAgentRecord;
  const {keystoreAgent} = await profileAgents.getAgents(
    {profileAgent, secrets});
  // we will need this to delegate and invoke
  // the profile signer is authorized to sign with the profileAgent's key?
  const {profileSigner} = await getSigners({profileAgentRecord, keystoreAgent});
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
  profileAgentContent = {},
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
  const {profileAgent} = profileAgentRecord;
  const {
    id: profileAgentId,
    zcaps: agentZcaps
  } = profileAgent;
  const {profileCapabilityInvocationKey} = agentZcaps;
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
  const profile = {
    ...profileContent,
    id: profileId,
    type: ['User', 'Profile'],
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
  const profileDocZcap = await delegateCapability(
    {signer: invocationSigner, request: delegateUserEdvDocumentRequest});
  const delegateUserEdvRequest = {
    referenceId: 'user-edv-documents',
    allowedAction: ['read', 'write'],
    controller: profileAgentId,
    invocationTarget: {
      invocationTarget: documentsUrl,
      type: 'urn:edv:documents'
    },
    parentCapability: capability
  };
  const delegateUserKakRequest = {
    referenceId: 'user-edv-kak',
    allowedAction: ['deriveSecret', 'sign'],
    controller: profileAgentId,
    invocationTarget: {
      id: keyAgreementKey.id,
      type: keyAgreementKey.type,
      verificationMethod: keyAgreementKey.id
    },
    parentCapability: keyAgreementKey.id
  };
  const delegateUserHmacRequest = {
    referenceId: 'user-edv-hmac',
    allowedAction: 'sign',
    controller: profileAgentId,
    invocationTarget: {
      id: hmac.id,
      type: hmac.type,
      verificationMethod: hmac.id,
      parentCapability: hmac.id
    }
  };
  const userKak = await delegateCapability(
    {signer: invocationSigner, request: delegateUserKakRequest});
  const userHmac = await delegateCapability(
    {signer: invocationSigner, request: delegateUserHmacRequest});
  const userDocument = await delegateCapability(
    {signer: invocationSigner, request: delegateUserEdvRequest});
  const userEdvZcaps = [userKak, userHmac, userDocument];
  const agentDocId = await edvHelpers.generateRandom();
  const agentDoc = new EdvDocument({
    id: agentDocId,
    recipients,
    keyResolver,
    keyAgreementKey,
    hmac,
    capability,
    invocationSigner,
    client
  });
  const profileAgentZcaps = {};
  for(const zcap of userEdvZcaps) {
    profileAgentZcaps[zcap.referenceId] = zcap;
  }
  const profileAgentDocument = {
    name: 'root',
    ...profileAgentContent,
    id: profileAgentId,
    type: ['User', 'Agent'],
    zcaps: {
      [profileCapabilityInvocationKey.referenceId]:
        profileCapabilityInvocationKey,
      [profileDocZcap.referenceId]: profileDocZcap,
      ...profileAgentZcaps
    },
    authorizedDate: (new Date()).toISOString()
  };
  // TODO do this direct through bedrock-edv-storage
  await agentDoc.write({
    doc: {
      id: agentDocId,
      content: profileAgentDocument
    }
  });
  const delegateEdvDocumentRequest = {
    referenceId: profileAgentEdvDocument,
    allowedAction: ['read'],
    controller: profileAgentId,
    parentCapability: capability,
    invocationTarget: {
      id: `${documentsUrl}/${agentDocId}`,
      type: 'urn:edv:document'
    }
  };
  const userDocumentZcap = await delegateCapability(
    {signer: invocationSigner, request: delegateEdvDocumentRequest});
  const delegateEdvKakRequest = {
    referenceId: 'user-edv-kak',
    controller: profileAgentId,
    allowedAction: ['deriveSecret', 'sign'],
    invocationTarget: {
      id: keyAgreementKey.id,
      type: keyAgreementKey.type,
      verificationMethod: keyAgreementKey.id
    },
    parentCapability: keyAgreementKey.id
  };
  const userKakZcap = await delegateCapability(
    {signer: invocationSigner, request: delegateEdvKakRequest});
  const agentRecordZcaps = {
    ...agentZcaps,
    userDocument: userDocumentZcap,
    userKak: userKakZcap
  };
  profileAgent.sequence++;
  profileAgent.zcaps = agentRecordZcaps;
  await profileAgents.update({profileAgent});
  return {profile, profileAgent};
}

exports.insertIssuerAgent = insertIssuerAgent;
exports.stubPassport = stubPassport;

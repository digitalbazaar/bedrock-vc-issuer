const bedrock = require('bedrock');
const {httpsAgent} = require('bedrock-https-agent');
const edvStorage = require('bedrock-edv-storage');
const edvHelpers = require('bedrock-edv-storage/lib/helpers');
const {profiles, profileAgents} = require('bedrock-profile');
const keyResolver = require('bedrock-profile/lib/keyResolver');
const {delegateCapability} = require('bedrock-profile/lib/zcaps');
const kms = require('bedrock-profile/lib/kms');
const {Ed25519KeyPair} = require('crypto-ld');
const {EdvClient, EdvDocument} = require('edv-client');
const {
  AsymmetricKey,
  CapabilityAgent,
  KeystoreAgent,
  KmsClient
} = require('webkms-client');

const {config} = bedrock;

const {kmsModule, server: {baseUri}} = config;
const JWE_ALG = 'ECDH-ES+A256KW';
const profileAgentEdvDocument = 'profile-agent-edv-document';
const credentialsEdv = 'credentials-edv-document';

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
// FIXME: this copied from bedrock-web-profile-manager-utils
function deriveKeystoreId(id) {
  const urlObj = new URL(id);
  const paths = urlObj.pathname.split('/');
  return urlObj.origin +
    '/' +
    paths[1] + // "kms"
    '/' +
    paths[2] + // "keystores"
    '/' +
    paths[3]; // "<keystore_id>"
}

async function createIssuerKey({signer, type}) {
  const {capability: keystoreZcap} = signer;
  const id = deriveKeystoreId(keystoreZcap.invocationTarget.id);
  const keystore = await kms.getKeystore({id});
  const capabilityAgent = new CapabilityAgent({handle: 'primary', signer});
  const kmsClient = new KmsClient({keystore, httpsAgent});
  const keystoreAgent = new KeystoreAgent(
    {keystore, capabilityAgent, kmsClient});
  const key = await keystoreAgent.generateKey({type, kmsModule});
  const keyDescription = await key.getKeyDescription();
  const fingerprint = Ed25519KeyPair.fingerprintFromPublicKey(keyDescription);
  const verificationMethod = `did:key:${fingerprint}#${fingerprint}`;
  return {key, kmsClient, verificationMethod};
}

async function delegateEdvZcaps({
  controller,
  documentsUrl,
  edvClient,
  keyAgreementKey,
  hmac,
  capability,
  prefix,
  signer
}) {
  const references = {
    doc: `${prefix}-edv-documents`,
    hmac: `${prefix}-edv-hmac`,
    kak: `${prefix}-edv-kak`
  };
  const delegateUserEdvRequest = {
    referenceId: references.doc,
    allowedAction: ['read', 'write', 'delegate'],
    controller,
    invocationTarget: {
      invocationTarget: documentsUrl,
      type: 'urn:edv:documents'
    },
    parentCapability: capability
  };
  const delegateUserKakRequest = {
    referenceId: references.kak,
    allowedAction: ['deriveSecret', 'sign'],
    controller,
    invocationTarget: {
      id: keyAgreementKey.id,
      type: keyAgreementKey.type,
      verificationMethod: keyAgreementKey.id
    },
    parentCapability: keyAgreementKey.id
  };
  const delegateUserHmacRequest = {
    referenceId: references.hmac,
    allowedAction: 'sign',
    controller,
    invocationTarget: {
      id: hmac.id,
      type: hmac.type,
      verificationMethod: hmac.id,
      parentCapability: hmac.id
    }
  };
  return {
    [references.doc]: await delegateCapability(
      {signer, request: delegateUserEdvRequest, edvClient}),
    [references.kak]: await delegateCapability(
      {signer, request: delegateUserKakRequest, edvClient}),
    [references.hmac]: await delegateCapability(
      {signer, request: delegateUserHmacRequest, edvClient})
  };
}

async function delegateEdvDocument({
  profileAgentId,
  capability,
  client,
  docId,
  keyAgreementKey,
  documentsUrl,
  invocationSigner
}) {
  const delegateEdvDocumentRequest = {
    referenceId: profileAgentEdvDocument,
    allowedAction: ['read'],
    controller: profileAgentId,
    parentCapability: capability,
    invocationTarget: {
      id: `${documentsUrl}/${docId}`,
      type: 'urn:edv:document'
    }
  };
  const userDocumentZcap = await delegateCapability({
    signer: invocationSigner,
    edvClient: client,
    request: delegateEdvDocumentRequest
  });
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
  const userKakZcap = await delegateCapability({
    signer: invocationSigner,
    edvClient: client,
    request: delegateEdvKakRequest
  });
  return {
    userKak: userKakZcap,
    userDocument: userDocumentZcap
  };
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

// tests call on this to insert an issuerAgent
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
  const credentialEdv = await createProfileEdv({
    profileId,
    referenceId: credentialsEdv,
    keystoreAgent
  });
  const credentialZcaps = await delegateEdvZcaps({
    documentsUrl: `${credentialEdv.edvId}/documents`,
    capability: `${credentialEdv.edvId}/zcaps/documents`,
    hmac: credentialEdv.hmac,
    edvClient: {id: edvId},
    keyAgreementKey: credentialEdv.keyAgreementKey,
    controller: profileAgent.id,
    signer: profileSigner,
    prefix: 'credential'
  });
  const {key: issuerKey, kmsClient, verificationMethod} = await createIssuerKey(
    {signer: profileSigner, type: 'Ed25519VerificationKey2018'});
  const issuerKeyRequest = {
    referenceId: 'key-assertionMethod',
    revocationReferenceId: 'key-assertionMethod-revocations',
    // string should match KMS ops
    allowedAction: 'sign',
    invoker: profileId,
    delegator: profileId,
    invocationTarget: {
      id: issuerKey.id,
      type: issuerKey.type,
      verificationMethod,
      parentCapability: issuerKey.id
    }
  };
  const profileZcaps = {
    // this is the key used to actually issue a credential
    // this might be the wrong place to delegate this
    'key-assertionMethod': await delegateCapability({
      signer: profileSigner,
      request: issuerKeyRequest,
      kmsClient})
  };
  const profileContent = {
    name: 'test-user',
    type: ['User', 'Person'],
    zcaps: {...profileZcaps, ...credentialZcaps}
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
  const integration = await profileAgents.create(
    {profileId, token});
  const {profileAgent: issuerAgent} = integration;
  // delegate the credential zcaps to the issuer
  const credentialIssuerZcaps = await delegateEdvZcaps({
    documentsUrl: `${credentialEdv.edvId}/documents`,
    capability: `${credentialEdv.edvId}/zcaps/documents`,
    hmac: credentialEdv.hmac,
    edvClient: {id: edvId},
    keyAgreementKey: credentialEdv.keyAgreementKey,
    controller: issuerAgent.id,
    signer: profileSigner,
    prefix: 'credential'
  });
  const assertionKeyRequest = {
    referenceId: 'key-assertionMethod',
    revocationReferenceId: 'key-assertionMethod-revocations',
    // string should match KMS ops
    allowedAction: 'sign',
    invoker: issuerAgent.id,
    invocationTarget: {
      id: issuerKey.id,
      type: issuerKey.type,
      verificationMethod,
      parentCapability: issuerKey.id
    }
  };
  const issuerZcaps = {
    // this is the key used to actually issue a credential
    // this might be the wrong place to delegate this
    'key-assertionMethod': await delegateCapability({
      signer: profileSigner,
      request: assertionKeyRequest,
      kmsClient})
  };
  const capability = `${edvId}/zcaps/documents`;
  const documentsUrl = `${edvId}/documents`;
  const issuerContent = {
    name: 'test-issuer',
    // FIXME what is the type of the issuerContent?
    type: ['User', 'Person'],
    zcaps: {...credentialIssuerZcaps, ...issuerZcaps}
  };
  const issuerDocId = await edvHelpers.generateRandom();
  const issuerDoc = new EdvDocument({
    id: issuerDocId,
    recipients: result.recipients,
    keyResolver,
    keyAgreementKey,
    hmac,
    capability,
    invocationSigner: profileSigner,
    client: result.client
  });
  const issuerDocument = {
    name: 'root',
    ...issuerContent,
    id: issuerAgent.id,
    type: ['User', 'Agent'],
    zcaps: {...issuerAgent.zcaps, ...issuerContent.zcaps},
    authorizedDate: (new Date()).toISOString()
  };
  await issuerDoc.write({
    doc: {
      id: issuerDocId,
      content: issuerDocument
    }
  });

  // create a new document in the parent profile's user edv.
  // delegate access to the integration
  // puts all the keys it needs into the userDocument
  // remember to add a user Kak
  const issuerCaps = await delegateEdvDocument({
    profileAgentId: issuerAgent.id,
    capability,
    client: result.client,
    docId: issuerDocId,
    keyAgreementKey,
    documentsUrl,
    invocationSigner: profileSigner
  });
  issuerAgent.sequence++;
  issuerAgent.zcaps = {...issuerAgent.zcaps, ...issuerCaps};
  await profileAgents.update({profileAgent: issuerAgent});
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
  const profileDocZcap = await delegateCapability({
    signer: invocationSigner,
    edvClient: client,
    request: delegateUserEdvDocumentRequest
  });
  const userEdvZcaps = await delegateEdvZcaps({
    signer: invocationSigner,
    controller: profileAgentId,
    documentsUrl,
    hmac,
    edvClient: client,
    keyAgreementKey,
    prefix: 'user',
    capability
  });
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
  const profileAgentZcaps = {...userEdvZcaps};
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
  const userDocumentZcap = await delegateCapability({
    signer: invocationSigner,
    edvClient: client,
    request: delegateEdvDocumentRequest
  });
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
  const userKakZcap = await delegateCapability({
    signer: invocationSigner,
    edvClient: client,
    request: delegateEdvKakRequest
  });
  const agentRecordZcaps = {
    ...agentZcaps,
    userDocument: userDocumentZcap,
    userKak: userKakZcap
  };
  profileAgent.sequence++;
  profileAgent.zcaps = agentRecordZcaps;
  await profileAgents.update({profileAgent});
  return {profile, profileAgent, client, recipients};
}

exports.insertIssuerAgent = insertIssuerAgent;
exports.stubPassport = stubPassport;

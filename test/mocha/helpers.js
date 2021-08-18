/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brAccount = require('bedrock-account');
const brHttpsAgent = require('bedrock-https-agent');
const {delegateCapability, delegate} = require('bedrock-profile/lib/zcaps');
const edvStorage = require('bedrock-edv-storage');
const edvHelpers = require('bedrock-edv-storage/lib/helpers');
const {Ed25519VerificationKey2018} =
  require('@digitalbazaar/ed25519-verification-key-2018');
const {Ed25519VerificationKey2020} =
  require('@digitalbazaar/ed25519-verification-key-2020');
const {EdvClient, EdvDocument} = require('edv-client');
const {httpsAgent} = require('bedrock-https-agent');
const {httpClient} = require('@digitalbazaar/http-client');
const kms = require('bedrock-profile/lib/kms');
const {profiles, profileAgents} = require('bedrock-profile');

const SUPPORTED_KEY_PAIRS = new Map();
SUPPORTED_KEY_PAIRS.set(
  'Ed25519VerificationKey2018', Ed25519VerificationKey2018);
SUPPORTED_KEY_PAIRS.set(
  'Ed25519VerificationKey2020', Ed25519VerificationKey2020);

const {
  AsymmetricKey,
  CapabilityAgent,
  KeystoreAgent,
  KmsClient
} = require('@digitalbazaar/webkms-client');

const {config} = bedrock;

const {kmsModule, server: {baseUri}} = config;
const JWE_ALG = 'ECDH-ES+A256KW';
const profileAgentEdvDocument = 'profile-agent-edv-document';
const profileEdvDocument = 'profile-edv-document';
const credentialsEdv = 'credentials-edv-document';

const keyResolver = async ({id} = {}) => {
  const {httpsAgent} = brHttpsAgent;
  const response = await httpClient.get(id, {
    agent: httpsAgent
  });
  return response.data;
};

async function insertAccount({account = {}, meta = {}}) {
  return brAccount.insert({actor: null, account, meta});
}

async function delegateSigner({profileAgentRecord}) {
  const {profileAgent, secrets} = profileAgentRecord;
  const ca = await CapabilityAgent.fromSecret(
    {handle: 'primary', secret: secrets.seed});
  const invoker = ca.id.split('#')[0];
  const zcap = await profileAgents.delegateCapabilityInvocationKey(
    {profileAgent, invoker, secrets});
  const kmsClient = new KmsClient({httpsAgent});
  const rootSigner = new AsymmetricKey({
    capability: zcap,
    invocationSigner: ca.getSigner(),
    kmsClient
  });
  return rootSigner;
}

async function getProfileKeystoreAgent({profileSigner}) {
  const {capability: zcap} = profileSigner;
  const keystoreId = deriveKeystoreId(zcap.invocationTarget.id);
  const keystore = await KmsClient.getKeystore({id: keystoreId, httpsAgent});
  const capabilityAgent = new CapabilityAgent(
    {handle: 'primary', signer: profileSigner});
  const kmsClient = new KmsClient({httpsAgent});
  return new KeystoreAgent({keystore, capabilityAgent, kmsClient});
}

// this is supposed to emulate accessManager's createUser function
async function createUser({
  token,
  profile,
  recipients,
  client,
  keyAgreementKey,
  hmac,
  profileZcaps,
  invocationSigner,
  credentialEdv,
  issuerKey,
  publicAlias,
  edvId,
  privateKmsBaseUrl,
  publicKmsBaseUrl
}) {
  const integration = await profileAgents.create(
    {profileId: profile.id, token, privateKmsBaseUrl, publicKmsBaseUrl});
  const {profileAgent: issuerAgent} = integration;
  // delegate the credential zcaps to the issuer
  const credentialIssuerZcaps = await delegateEdvZcaps({
    documentsUrl: `${credentialEdv.edvId}/documents`,
    capability: `${credentialEdv.edvId}/zcaps/documents`,
    hmac: credentialEdv.hmac,
    edvClient: credentialEdv.edvClient,
    keyAgreementKey: credentialEdv.keyAgreementKey,
    controller: issuerAgent.id,
    signer: invocationSigner,
    prefix: 'credential'
  });
  const assertionKeyRequest = {
    '@context': 'https://w3id.org/security/v2',
    id: `urn:zcap:${await edvHelpers.generateRandom()}`,
    referenceId: 'key-assertionMethod',
    // string should match KMS ops
    allowedAction: 'sign',
    controller: issuerAgent.id,
    parentCapability: profileZcaps['key-assertionMethod'].id,
    invocationTarget: {
      id: issuerKey.id,
      type: issuerKey.type,
      publicAlias
    }
  };
  const issuerZcaps = {
    // this is the key used to actually issue a credential
    'key-assertionMethod': await delegate({
      signer: invocationSigner,
      zcap: assertionKeyRequest,
      capabilityChain: [issuerKey.id, profileZcaps['key-assertionMethod']]
    })
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
    recipients,
    keyResolver,
    keyAgreementKey,
    hmac,
    capability,
    invocationSigner,
    client
  });
  const issuerDocument = {
    name: 'root',
    ...issuerContent,
    id: issuerAgent.id,
    type: ['Application'],
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
  const issuerCaps = await delegateAgentRecordZcaps({
    profileAgentId: issuerAgent.id,
    edvParentCapability: capability,
    client,
    docId: issuerDocId,
    keyAgreementKey,
    documentsUrl,
    invocationSigner
  });
  issuerAgent.sequence++;
  issuerAgent.zcaps = {...issuerAgent.zcaps, ...issuerCaps};
  await profileAgents.update({profileAgent: issuerAgent});
  return integration;
}

async function createIssuerKey({profileSigner, type}) {
  const {capability} = profileSigner;
  let keystore;
  if(capability) {
    const id = deriveKeystoreId(capability.invocationTarget.id);
    keystore = await kms.getKeystore({id});
  } else {
    const id = profileSigner.kmsClient.keystore;
    keystore = await kms.getKeystore({id});
  }
  const kmsClient = new KmsClient({keystore, httpsAgent});
  const keystoreAgent = await getProfileKeystoreAgent({profileSigner});
  const key = await keystoreAgent.generateKey({type, kmsModule});
  const KeyPair = SUPPORTED_KEY_PAIRS.get(type);
  const keyDescription = await key.getKeyDescription();
  const keyPair = await KeyPair.from(keyDescription);
  const fingerprint = keyPair.fingerprint();
  const publicAlias = `did:key:${fingerprint}#${fingerprint}`;
  return {key, kmsClient, publicAlias};
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
      publicAlias: keyAgreementKey.id
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
      publicAlias: hmac.id,
    },
    parentCapability: hmac.id
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

async function delegateAgentRecordZcaps({
  profileAgentId,
  edvParentCapability,
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
    parentCapability: edvParentCapability,
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
      publicAlias: keyAgreementKey.id
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

async function getSigners({profileAgentRecord}) {
  const {profileAgent} = profileAgentRecord;
  const {profileCapabilityInvocationKey} = profileAgent.zcaps;
  const agentSigner = await delegateSigner({profileAgentRecord});
  const profileSigner = new AsymmetricKey({
    capability: profileCapabilityInvocationKey,
    invocationSigner: agentSigner,
    kmsClient: new KmsClient({httpsAgent}),
    kmsId: profileCapabilityInvocationKey.parentCapability,
    type: profileCapabilityInvocationKey.invocationTarget.type
  });
  return {agentSigner, profileSigner};
}

// tests call on this to insert an issuerAgent
async function insertIssuerAgent({
  id, token, didMethod, privateKmsBaseUrl, publicKmsBaseUrl
}) {
  // this is the profile associated with an issuer account
  const {id: profileId} = await profiles.create({
    accountId: id, didMethod, privateKmsBaseUrl, publicKmsBaseUrl});
  console.log(profileId, '<><><><><>profileId');
  const profileAgentRecord = await profileAgents.getByProfile(
    {profileId, accountId: id, includeSecrets: true});
  const {profileAgent} = profileAgentRecord;
  // we will need this to delegate and invoke
  // the profile signer is authorized to sign with the profileAgent's key?
  const {agentSigner, profileSigner} = await getSigners({profileAgentRecord});
  const keystoreAgent = await getProfileKeystoreAgent({profileSigner});
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
    signer: agentSigner,
    prefix: 'credential'
  });
  const {key: issuerKey, kmsClient, publicAlias} = await createIssuerKey(
    {profileSigner, type: 'Ed25519VerificationKey2018'});
  const issuerKeyRequest = {
    referenceId: 'key-assertionMethod',
    revocationReferenceId: 'key-assertionMethod-revocations',
    // string should match KMS ops
    allowedAction: 'sign',
    controller: profileId,
    parentCapability: issuerKey.id,
    invocationTarget: {
      id: issuerKey.id,
      type: issuerKey.type,
      publicAlias,
    }
  };
  const profileZcaps = {
    // this is the key used to actually issue a credential
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
  result.profile.account = id;
  // this is the profileAgent created for an issuer instance integration
  // it is used to issue a credential.
  const integration = await createUser({
    token,
    hmac,
    keyAgreementKey,
    profileZcaps,
    credentialEdv,
    issuerKey,
    edvId,
    publicKmsBaseUrl,
    privateKmsBaseUrl,
    publicAlias,
    invocationSigner: profileSigner,
    ...result
  });
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
  const edvClient = new EdvClient(
    {httpsAgent, id: edvId, keyResolver, keyAgreementKey, hmac});
  return {keyAgreementKey, hmac, config: result, edvId, edvClient};
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
    // FIXME ensure profileCapabilityInvocationKey is removed
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
    referenceId: profileEdvDocument,
    // the profile agent is only allowed to read its own doc
    allowedAction: ['read'],
    controller: profileAgentId,
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
      publicAlias: keyAgreementKey.id
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

/**
 * Stubs a sinon passport stub.
*/
const _actor = {id: 'theMockControllerId'};
function stubPassport({passportStub, account = {}, actor = _actor}) {
  passportStub.callsFake((req, res, next) => {
    req.user = {
      account,
      actor
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

function shouldBeAValidationError(err) {
  err.status.should.equal(400);
  const {data = {}} = err;
  data.should.have.property('message');
  data.message.should.be.a('string');
  data.should.have.property('type');
  data.type.should.be.a('string');
  data.type.should.contain('ValidationError');
  data.should.have.property('details');
  data.should.have.property('cause');
}

exports.shouldBeAValidationError = shouldBeAValidationError;
exports.insertIssuerAgent = insertIssuerAgent;
exports.stubPassport = stubPassport;
exports.insertAccount = insertAccount;

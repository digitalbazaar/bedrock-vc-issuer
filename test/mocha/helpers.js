/*
 * Copyright (c) 2019-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';
import {importJWK, SignJWT} from 'jose';
import {KeystoreAgent, KmsClient} from '@digitalbazaar/webkms-client';
import {agent} from '@bedrock/https-agent';
import {AsymmetricKey} from '@digitalbazaar/webkms-client';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {decodeList} from '@digitalbazaar/vc-bitstring-status-list';
import {decodeList as decodeList2021} from '@digitalbazaar/vc-status-list';
import {didIo} from '@bedrock/did-io';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {EdvClient} from '@digitalbazaar/edv-client';
import {getAppIdentity} from '@bedrock/app-identity';
import {httpClient} from '@digitalbazaar/http-client';
import {httpsAgent} from '@bedrock/https-agent';
import {ZcapClient} from '@digitalbazaar/ezcap';

import {mockData} from './mock.data.js';

const edvBaseUrl = `${mockData.baseUrl}/edvs`;
const kmsBaseUrl = `${mockData.baseUrl}/kms`;

const FIVE_MINUTES = 1000 * 60 * 5;

export async function createConfig({
  serviceType, url, capabilityAgent, ipAllowList, meterId, zcaps,
  configOptions = {}, oauth2 = false
} = {}) {
  if(!meterId) {
    // create a meter
    ({id: meterId} = await createMeter({capabilityAgent, serviceType}));
  }

  // create service object
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    meterId,
    ...configOptions
  };
  if(ipAllowList) {
    config.ipAllowList = ipAllowList;
  }
  if(zcaps) {
    config.zcaps = zcaps;
  }
  if(oauth2) {
    const {baseUri} = bedrock.config.server;
    config.authorization = {
      oauth2: {
        issuerConfigUrl: `${baseUri}${mockData.oauth2IssuerConfigRoute}`
      }
    };
  }

  const zcapClient = createZcapClient({capabilityAgent});
  const response = await zcapClient.write({url, json: config});
  return response.data;
}

export function createRootZcap({url}) {
  return `urn:zcap:root:${encodeURIComponent(url)}`;
}

export async function createStatusConfig({
  capabilityAgent, ipAllowList, meterId, zcaps, oauth2 = false
} = {}) {
  const url = `${mockData.baseUrl}/statuses`;
  return createConfig({
    serviceType: 'vc-status',
    url, capabilityAgent, ipAllowList, meterId, zcaps, oauth2
  });
}

export async function createIssuerConfig({
  capabilityAgent, ipAllowList, meterId, zcaps, issueOptions,
  suiteName = 'Ed25519Signature2020', statusListOptions, oauth2 = false
} = {}) {
  const url = `${mockData.baseUrl}/issuers`;
  // issuer-specific options
  const configOptions = {
    issueOptions: issueOptions ?? {suiteName}
  };
  if(statusListOptions) {
    configOptions.statusListOptions = statusListOptions;
  }
  return createConfig({
    serviceType: 'vc-issuer',
    url, capabilityAgent, ipAllowList, meterId, zcaps, configOptions, oauth2
  });
}

export async function createIssuerConfigAndDependencies({
  capabilityAgent, ipAllowList, meterId, zcaps, issueOptions,
  suiteName = 'Ed25519Signature2020', statusListOptions, oauth2 = false,
  depOptions
}) {
  let statusConfig;
  let issuerCreateStatusListZcap;
  if(statusListOptions) {
    ({
      statusConfig,
      issuerCreateStatusListZcap
    } = await provisionDependencies(depOptions));
    zcaps = {
      ...zcaps
    };
    for(const {zcapReferenceIds} of statusListOptions) {
      zcaps[zcapReferenceIds.createCredentialStatusList] =
        issuerCreateStatusListZcap;
    }
  }
  const issuerConfig = await createIssuerConfig({
    capabilityAgent, ipAllowList, meterId, zcaps, issueOptions,
    suiteName, statusListOptions, oauth2
  });
  return {
    issuerConfig,
    issuerId: issuerConfig.id,
    rootZcap: createRootZcap({url: issuerConfig.id}),
    statusId: statusConfig?.id,
    statusRootZcap: statusConfig && createRootZcap({url: statusConfig.id})
  };
}

export async function createMeter({capabilityAgent, serviceType} = {}) {
  // create signer using the application's capability invocation key
  const {keys: {capabilityInvocationKey}} = getAppIdentity();

  const zcapClient = new ZcapClient({
    agent: httpsAgent,
    invocationSigner: capabilityInvocationKey.signer(),
    SuiteClass: Ed25519Signature2020
  });

  // create a meter
  const meterService = `${bedrock.config.server.baseUri}/meters`;
  let meter = {
    controller: capabilityAgent.id,
    product: {
      // mock ID for service type
      id: mockData.productIdMap.get(serviceType)
    }
  };
  ({data: {meter}} = await zcapClient.write({url: meterService, json: meter}));

  // return full meter ID
  const {id} = meter;
  return {id: `${meterService}/${id}`};
}

export async function getConfig({id, capabilityAgent, accessToken}) {
  if(accessToken) {
    // do OAuth2
    const {data} = await httpClient.get(id, {
      agent: httpsAgent,
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    return data;
  }
  if(!capabilityAgent) {
    throw new Error('Either "capabilityAgent" or "accessToken" is required.');
  }
  // do zcap
  const zcapClient = createZcapClient({capabilityAgent});
  const {data} = await zcapClient.read({url: id});
  return data;
}

export async function getOAuth2AccessToken({
  configId, action, target, exp, iss, nbf, typ = 'at+jwt'
}) {
  const scope = `${action}:${target}`;
  const builder = new SignJWT({scope})
    .setProtectedHeader({alg: 'EdDSA', typ})
    .setIssuer(iss ?? mockData.oauth2Config.issuer)
    .setAudience(configId);
  if(exp !== undefined) {
    builder.setExpirationTime(exp);
  } else {
    // default to 5 minute expiration time
    builder.setExpirationTime('5m');
  }
  if(nbf !== undefined) {
    builder.setNotBefore(nbf);
  }
  const key = await importJWK({...mockData.ed25519KeyPair, alg: 'EdDSA'});
  return builder.sign(key);
}

export async function createEdv({
  capabilityAgent, keystoreAgent, keyAgreementKey, hmac, meterId
}) {
  if(!meterId) {
    // create a meter for the keystore
    ({id: meterId} = await createMeter({
      capabilityAgent, serviceType: 'edv'
    }));
  }

  if(!(keyAgreementKey && hmac) && keystoreAgent) {
    // create KAK and HMAC keys for edv config
    ([keyAgreementKey, hmac] = await Promise.all([
      keystoreAgent.generateKey({type: 'keyAgreement'}),
      keystoreAgent.generateKey({type: 'hmac'})
    ]));
  }

  // create edv
  const newEdvConfig = {
    sequence: 0,
    controller: capabilityAgent.id,
    keyAgreementKey: {id: keyAgreementKey.id, type: keyAgreementKey.type},
    hmac: {id: hmac.id, type: hmac.type},
    meterId
  };

  const edvConfig = await EdvClient.createEdv({
    config: newEdvConfig,
    httpsAgent,
    invocationSigner: capabilityAgent.getSigner(),
    url: edvBaseUrl
  });

  const edvClient = new EdvClient({
    id: edvConfig.id,
    keyResolver,
    keyAgreementKey,
    hmac,
    httpsAgent
  });

  return {edvClient, edvConfig, hmac, keyAgreementKey};
}

export async function delegateEdvZcaps({
  edvConfig, hmac, keyAgreementKey, serviceAgent, capabilityAgent,
  zcaps = {}
} = {}) {
  const {id: edvId} = edvConfig;
  zcaps.edv = await delegate({
    controller: serviceAgent.id,
    delegator: capabilityAgent,
    invocationTarget: edvId
  });
  zcaps.hmac = await delegate({
    capability: 'urn:zcap:root:' +
      encodeURIComponent(parseKeystoreId(hmac.id)),
    controller: serviceAgent.id,
    invocationTarget: hmac.id,
    delegator: capabilityAgent
  });
  zcaps.keyAgreementKey = await delegate({
    capability: 'urn:zcap:root:' +
      encodeURIComponent(parseKeystoreId(keyAgreementKey.kmsId)),
    controller: serviceAgent.id,
    invocationTarget: keyAgreementKey.kmsId,
    delegator: capabilityAgent
  });
  return zcaps;
}

export async function delegateAssertionMethodZcaps({
  envelope, cryptosuites = [], serviceAgent,
  capabilityAgent, zcaps = {}
} = {}) {
  // can treat any envelope input as a cryptosuite here
  const suites = (cryptosuites || []).slice();
  if(envelope) {
    suites.push(envelope);
  }

  // delegate any assertion method keys not yet delegated
  for(const suite of suites) {
    // only delegate zcap once as the service agent is always the same
    let referenceId = suite.zcapReferenceIds?.assertionMethod;
    if(!referenceId) {
      const {assertionMethodKey} = suite;
      const zcap = await delegate({
        capability: 'urn:zcap:root:' +
          encodeURIComponent(parseKeystoreId(assertionMethodKey.kmsId)),
        controller: serviceAgent.id,
        invocationTarget: assertionMethodKey.kmsId,
        delegator: capabilityAgent
      });
      referenceId = zcap.id;
      suite.zcaps = suite.zcaps ?? {};
      suite.zcaps[referenceId] = zcap;
      suite.zcapReferenceIds = suite.zcapReferenceIds ?? {};
      suite.zcapReferenceIds.assertionMethod = referenceId;
    }
    zcaps[referenceId] = suite.zcaps[referenceId];
  }
  return zcaps;
}

export async function createKeystore({
  capabilityAgent, ipAllowList, meterId,
  kmsModule = 'ssm-v1'
}) {
  if(!meterId) {
    // create a meter for the keystore
    ({id: meterId} = await createMeter(
      {capabilityAgent, serviceType: 'webkms'}));
  }

  // create keystore
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    meterId,
    kmsModule
  };
  if(ipAllowList) {
    config.ipAllowList = ipAllowList;
  }

  return KmsClient.createKeystore({
    url: `${kmsBaseUrl}/keystores`,
    config,
    invocationSigner: capabilityAgent.getSigner(),
    httpsAgent
  });
}

export async function createKeystoreAgent({capabilityAgent, ipAllowList}) {
  let err;
  let keystore;
  try {
    keystore = await createKeystore({capabilityAgent, ipAllowList});
  } catch(e) {
    err = e;
  }
  assertNoError(err);

  // create kmsClient only required because we need to use httpsAgent
  // that accepts self-signed certs used in test suite
  const kmsClient = new KmsClient({httpsAgent});
  const keystoreAgent = new KeystoreAgent({
    capabilityAgent,
    keystoreId: keystore.id,
    kmsClient
  });

  return keystoreAgent;
}

export function createZcapClient({
  capabilityAgent, delegationSigner, invocationSigner
}) {
  const signer = capabilityAgent && capabilityAgent.getSigner();
  return new ZcapClient({
    agent: httpsAgent,
    invocationSigner: invocationSigner || signer,
    delegationSigner: delegationSigner || signer,
    SuiteClass: Ed25519Signature2020
  });
}

export async function delegate({
  capability, controller, invocationTarget, expires, allowedActions,
  delegator
}) {
  const zcapClient = createZcapClient({capabilityAgent: delegator});
  expires = expires || (capability && capability.expires) ||
    new Date(Date.now() + FIVE_MINUTES).toISOString().slice(0, -5) + 'Z';
  return zcapClient.delegate({
    capability, controller, expires, invocationTarget, allowedActions
  });
}

export async function getCredentialStatus({
  verifiableCredential, statusPurpose, listLength
}) {
  // get SLC for the VC
  let {credentialStatus} = verifiableCredential;
  if(Array.isArray(credentialStatus)) {
    // find matching status purpose
    credentialStatus = credentialStatus.find(
      cs => cs.statusPurpose === statusPurpose);
    if(!credentialStatus) {
      throw new Error(
        `Credential status with matching status purpose "${statusPurpose}" ` +
        'not found.');
    }
  }
  let {statusListCredential} = credentialStatus;
  let statusListIndex;
  let expandedCredentialStatus;
  if(statusListCredential) {
    statusListIndex = parseInt(credentialStatus.statusListIndex, 10);
  } else {
    if(credentialStatus.type !== 'TerseBitstringStatusListEntry') {
      throw new Error('Status list credential missing from credential status.');
    }
    // compute `statusListCredential` from other params
    const listIndex = Math.floor(
      credentialStatus.terseStatusListIndex / listLength);
    statusListIndex = credentialStatus.terseStatusListIndex % listLength;
    const {terseStatusListBaseUrl} = credentialStatus;
    statusListCredential =
      `${terseStatusListBaseUrl}/${statusPurpose}/${listIndex}`;
    expandedCredentialStatus = {
      type: 'BitstringStatusListEntry',
      statusListCredential,
      statusListIndex: `${statusListIndex}`,
      statusPurpose
    };
  }
  let {data: slc} = await httpClient.get(
    statusListCredential, {agent: httpsAgent});

  // parse enveloped VC as needed
  if(slc.type === 'EnvelopedVerifiableCredential') {
    slc = parseEnvelope({verifiableCredential: slc});
  }

  const {encodedList} = slc.credentialSubject;
  let list;
  if(slc.type.includes('StatusList2021Credential')) {
    list = await decodeList2021({encodedList});
  } else {
    list = await decodeList({encodedList});
  }
  const status = list.getStatus(statusListIndex);
  return {
    status, statusListCredential, expandedCredentialStatus, credentialStatus
  };
}

export async function revokeDelegatedCapability({
  serviceObjectId, capabilityToRevoke, invocationSigner
}) {
  const url = `${serviceObjectId}/zcaps/revocations/` +
    encodeURIComponent(capabilityToRevoke.id);
  const zcapClient = createZcapClient({invocationSigner});
  return zcapClient.write({url, json: capabilityToRevoke});
}

async function keyResolver({id}) {
  // support DID-based keys only
  if(id.startsWith('did:')) {
    return didIo.get({url: id});
  }
  // support HTTP-based keys; currently a requirement for WebKMS
  const {data} = await httpClient.get(id, {agent: httpsAgent});
  return data;
}

export async function provisionDependencies({
  did, cryptosuites = [], envelope, suiteOptions,
  status = true, zcaps = false
} = {}) {
  const secret = '53ad64ce-8e1d-11ec-bb12-10bf48838a41';
  const handle = 'test';
  const capabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

  // create keystore for capability agent
  const keystoreAgent = await createKeystoreAgent({capabilityAgent});

  const suites = cryptosuites.slice();
  if(envelope) {
    suites.push(envelope);
  }
  if(suites.length > 0) {
    // auto-generate DID using `did:key` if no `did` given
    const publicAliasTemplate = did ?
      `${did}#{publicKeyMultibase}` :
      'did:key:{publicKeyMultibase}#{publicKeyMultibase}';

    // generate an assertion method key for each cryptosuite and / or envelope
    for(const suite of suites) {
      const {algorithm} = suite;
      if(suite.assertionMethodKey) {
        // key already set
        continue;
      }
      let assertionMethodKey;
      if(['P-256', 'P-384', 'Bls12381G2'].includes(algorithm)) {
        assertionMethodKey = await _generateMultikey({
          keystoreAgent,
          type: `urn:webkms:multikey:${algorithm}`,
          publicAliasTemplate
        });
      } else {
        assertionMethodKey = await keystoreAgent.generateKey({
          type: 'asymmetric',
          publicAliasTemplate
        });
      }
      suite.assertionMethodKey = assertionMethodKey;
    }

    if(zcaps) {
      // create EDV for storage (creating hmac and kak in the process)
      const {
        edvConfig,
        hmac,
        keyAgreementKey
      } = await createEdv({capabilityAgent, keystoreAgent});

      // get service agent to delegate to
      const serviceAgentUrl =
        `${mockData.baseUrl}/service-agents/${encodeURIComponent('vc-issuer')}`;
      const {data: serviceAgent} = await httpClient.get(
        serviceAgentUrl, {agent});

      // delegate edv, hmac, and key agreement key zcaps to service agent
      zcaps = await delegateEdvZcaps({
        edvConfig, hmac, keyAgreementKey, serviceAgent,
        capabilityAgent
      });

      const assertionMethodZcaps = did ? zcaps : {};

      // delegate zcaps for each cryptosuite
      await delegateAssertionMethodZcaps({
        envelope, cryptosuites, serviceAgent, capabilityAgent,
        zcaps: assertionMethodZcaps
      });

      // when no `did` is provided, presume legacy format and include
      // an `assertionMethod` zcap pointing to the first cryptosuite's zcap
      if(!did) {
        // set single `assertionMethod` zcap reference ID
        zcaps.assertionMethod = assertionMethodZcaps[
          cryptosuites[0].zcapReferenceIds.assertionMethod];
      }
    }
  }

  if(!status) {
    return {capabilityAgent, keystoreAgent, zcaps};
  }

  const {
    statusConfig,
    issuerCreateStatusListZcap,
    assertionMethodKey
  } = await provisionStatus({
    did, capabilityAgent, keystoreAgent, suiteOptions
  });

  return {
    statusConfig, issuerCreateStatusListZcap, capabilityAgent, keystoreAgent,
    zcaps,
    // legacy `assertionMethodKey` only generated when not using status
    // `cryptosuites` nor status `envelope`
    assertionMethodKey
  };
}

export async function provisionIssuerForStatus({
  did, capabilityAgent, keystoreAgent, suiteOptions
}) {
  // create EDV for storage (creating hmac and kak in the process)
  const {
    edvConfig,
    hmac,
    keyAgreementKey
  } = await createEdv({capabilityAgent, keystoreAgent});

  // get service agent to delegate to
  const issuerServiceAgentUrl =
    `${mockData.baseUrl}/service-agents/${encodeURIComponent('vc-issuer')}`;
  const {data: issuerServiceAgent} = await httpClient.get(
    issuerServiceAgentUrl, {agent});

  // delegate edv, hmac, and key agreement key zcaps to service agent
  const zcaps = await delegateEdvZcaps({
    edvConfig, hmac, keyAgreementKey, serviceAgent: issuerServiceAgent,
    capabilityAgent
  });

  const {statusOptions} = suiteOptions;

  // if neither status cryptosuites nor envelope are provided, then generate
  // assertion method key for status VC issuer
  let assertionMethodKey;
  if(!(statusOptions.cryptosuites || statusOptions.envelope)) {
    // generate key for signing VCs (make it a did:key DID for simplicity if
    // no DID is given)
    const didTemplate = did ?? 'did:key:{publicKeyMultibase}';
    const publicAliasTemplate = didTemplate + '#{publicKeyMultibase}';
    const algorithm = statusOptions.algorithm ?? suiteOptions.algorithm;
    if(['P-256', 'P-384'].includes(algorithm)) {
      assertionMethodKey = await _generateMultikey({
        keystoreAgent,
        type: `urn:webkms:multikey:${algorithm}`,
        publicAliasTemplate
      });
    } else {
      assertionMethodKey = await keystoreAgent.generateKey({
        type: 'asymmetric',
        publicAliasTemplate
      });
    }

    // delegate assertion method zcap to service agent
    zcaps.assertionMethod = await delegate({
      capability: createRootZcap({
        url: parseKeystoreId(assertionMethodKey.kmsId)
      }),
      controller: issuerServiceAgent.id,
      invocationTarget: assertionMethodKey.kmsId,
      delegator: capabilityAgent
    });
  }

  // create issuer instance w/ oauth2-based authz
  const {suiteName} = statusOptions;
  let issueOptions;
  if(statusOptions.cryptosuites || statusOptions.envelope) {
    // can treat any envelope input as a cryptosuite here
    const suites = (statusOptions.cryptosuites || []).slice();
    if(statusOptions.envelope) {
      suites.push(statusOptions.envelope);
    }

    // delegate assertion method keys
    await delegateAssertionMethodZcaps({
      cryptosuites: suites,
      serviceAgent: issuerServiceAgent, capabilityAgent, zcaps
    });

    // generate issue options based on given cryptosuites and envelope
    issueOptions = {
      issuer: did
    };
    if(statusOptions.cryptosuites) {
      issueOptions.cryptosuites = statusOptions.cryptosuites
        .map(({name, zcapReferenceIds}) => ({name, zcapReferenceIds}));
    }
    if(statusOptions.envelope) {
      issueOptions.envelope = {
        format: statusOptions.envelope.format,
        zcapReferenceIds: statusOptions.envelope.zcapReferenceIds
      };
    }
  }
  const issuerConfig = await createIssuerConfig(
    {capabilityAgent, zcaps, suiteName, issueOptions, oauth2: true});
  const {id: issuerId} = issuerConfig;
  const issuerRootZcap = `urn:zcap:root:${encodeURIComponent(issuerId)}`;

  // delegate issuer root zcap to status service
  const statusServiceAgentUrl =
    `${mockData.baseUrl}/service-agents/${encodeURIComponent('vc-status')}`;
  const {data: exchangerServiceAgent} = await httpClient.get(
    statusServiceAgentUrl, {agent});

  // zcap to issue a credential
  const statusIssueZcap = await delegate({
    capability: issuerRootZcap,
    controller: exchangerServiceAgent.id,
    invocationTarget: `${issuerId}/credentials/issue`,
    delegator: capabilityAgent
  });

  return {issuerConfig, statusIssueZcap, assertionMethodKey};
}

export async function provisionStatus({
  did, capabilityAgent, keystoreAgent, suiteOptions
}) {
  const {
    issuerConfig,
    statusIssueZcap,
    assertionMethodKey
  } = await provisionIssuerForStatus({
    did, capabilityAgent, keystoreAgent, suiteOptions
  });

  const zcaps = {
    issue: statusIssueZcap
  };

  // create status instance w/ oauth2-based authz
  const statusConfig = await createStatusConfig(
    {capabilityAgent, zcaps, oauth2: true});
  const {id: statusId} = statusConfig;
  const statusRootZcap = `urn:zcap:root:${encodeURIComponent(statusId)}`;

  // delegate status root zcap to issuer service
  const issuerServiceAgentUrl =
    `${mockData.baseUrl}/service-agents/${encodeURIComponent('vc-issuer')}`;
  const {data: issuerServiceAgent} = await httpClient.get(
    issuerServiceAgentUrl, {agent});

  // zcap to create a status list
  const issuerCreateStatusListZcap = await delegate({
    capability: statusRootZcap,
    controller: issuerServiceAgent.id,
    invocationTarget: `${statusId}/status-lists`,
    delegator: capabilityAgent
  });

  return {
    issuerConfig, statusConfig, issuerCreateStatusListZcap,
    assertionMethodKey
  };
}

export async function _generateMultikey({
  keystoreAgent, type, publicAliasTemplate
}) {
  const {capabilityAgent, kmsClient} = keystoreAgent;
  const invocationSigner = capabilityAgent.getSigner();
  const {keyId, keyDescription} = await kmsClient.generateKey({
    type,
    suiteContextUrl: 'https://w3id.org/security/multikey/v1',
    invocationSigner,
    publicAliasTemplate
  });
  const {id} = keyDescription;
  ({type} = keyDescription);
  return new AsymmetricKey({
    id, kmsId: keyId, type, invocationSigner, kmsClient, keyDescription
  });
}

const serviceCoreConfigCollection =
  database.collections['service-core-config-vc-issuer'];

export async function updateConfig({configId, referenceId}) {
  const updateReferenceId = {
    'config.zcaps.assertionMethod': `config.zcaps.${referenceId}`
  };
  await serviceCoreConfigCollection.updateOne({
    'config.id': configId,
  }, {
    $rename: updateReferenceId
  });
}

export async function findConfig({configId}) {
  return serviceCoreConfigCollection.findOne({
    'config.id': configId,
  });
}

export function parseKeystoreId(keyId) {
  // key ID format: <baseUrl>/<keystores-path>/<keystore-id>/keys/<key-id>
  const idx = keyId.lastIndexOf('/keys/');
  if(idx === -1) {
    throw new Error(`Invalid key ID "${keyId}".`);
  }
  return keyId.slice(0, idx);
}

export function parseEnvelope({verifiableCredential}) {
  const {id} = verifiableCredential;
  const commaIndex = id.indexOf(',');
  const format = id.slice('data:'.length, commaIndex);

  // VC-JWT envelope
  if(format === 'application/jwt') {
    const data = id.slice(commaIndex + 1);
    // FIXME: consider adding verification of `data` (JWT)
    const split = data.split('.');
    const claimSet = JSON.parse(
      new TextDecoder().decode(base64url.decode(split[1])));
    return claimSet.vc;
  }
  throw new Error(`Unknown envelope format "${format}".`);
}

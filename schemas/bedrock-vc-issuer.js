/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {
  MAX_BLOCK_COUNT, MAX_BLOCK_SIZE, MAX_LIST_COUNT,
  MAX_STATUS_LIST_OPTIONS
} from '../lib/constants.js';
import {schemas} from '@bedrock/validation';

const VC_CONTEXT_1 = 'https://www.w3.org/2018/credentials/v1';
const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';
const VDL_CONTEXT_1 = 'https://w3id.org/vdl/v1';
const VDL_AAMVA_CONTEXT_1 = 'https://w3id.org/vdl/aamva/v1';

const context = {
  title: '@context',
  type: 'array',
  minItems: 1,
  items: {
    type: ['string', 'object']
  }
};

const zcapReferenceIds = {
  title: 'Authorization Capability Reference IDs',
  type: 'object',
  required: ['assertionMethod'],
  additionalProperties: false,
  properties: {
    assertionMethod: {
      type: 'string'
    }
  }
};

const mandatoryPointers = {
  type: 'array',
  minItems: 0,
  items: {
    type: 'string'
  }
};

const cryptosuite = {
  title: 'Cryptosuite Options',
  type: 'object',
  required: ['name', 'zcapReferenceIds'],
  additionalProperties: false,
  properties: {
    name: {
      type: 'string',
      // supported default suites in this version
      enum: [
        'Ed25519Signature2020',
        'ecdsa-rdfc-2019', 'eddsa-rdfc-2022',
        'ecdsa-jcs-2019', 'eddsa-jcs-2022',
        'ecdsa-sd-2023', 'ecdsa-xi-2023', 'bbs-2023'
      ]
    },
    options: {
      title: 'Cryptosuite options',
      type: 'object',
      additionalProperties: false,
      properties: {
        includeCreated: {
          type: 'boolean'
        },
        mandatoryPointers
      }
    },
    zcapReferenceIds
  }
};

const cryptosuites = {
  title: 'Cryptosuites',
  type: 'array',
  additionalItems: false,
  minItems: 1,
  items: cryptosuite
};

const envelope = {
  title: 'Envelope Options',
  type: 'object',
  // use only one of `mediaType` (preferred) or `format` (deprecated)
  oneOf: [
    {required: ['mediaType', 'zcapReferenceIds']},
    {required: ['format', 'zcapReferenceIds']}
  ],
  additionalProperties: false,
  properties: {
    mediaType: {
      type: 'string',
      // supported envelope media types in this version
      enum: ['application/jwt', 'application/mdl']
    },
    // deprecated; use `mediaType` instead
    format: {
      type: 'string',
      // supported envelope formats in this version
      enum: ['VC-JWT']
    },
    options: {
      title: 'Envelope options',
      type: 'object',
      additionalProperties: false,
      properties: {
        alg: {
          type: 'string',
          enum: ['ES256', 'EdDSA', 'Ed25519']
        },
        // X.509 certificate chain w/PEM-formatted certs for mDL issuance
        issuerCertificateChain: {
          type: 'array',
          minItems: 1,
          items: {type: 'string'}
        }
      }
    },
    zcapReferenceIds
  }
};

export const issueOptions = {
  title: 'Issue Options',
  type: 'object',
  oneOf: [{
    // preferred mechanism for specifying issuer and cryptosuites to sign with
    required: ['issuer', 'cryptosuites'],
    not: {
      required: ['suiteName']
    }
  }, {
    // preferred mechanism for specifying issuer and envelope to use
    required: ['issuer', 'envelope'],
    not: {
      required: ['suiteName']
    }
  }, {
    // legacy; for backwards compatibility only
    required: ['suiteName'],
    not: {
      required: ['issuer', 'cryptosuites', 'envelope']
    }
  }],
  additionalProperties: false,
  properties: {
    // modern
    issuer: {
      type: 'string'
    },
    // embedded proof security
    cryptosuites,
    // envelope security
    envelope,
    // legacy
    suiteName: {
      type: 'string',
      // supported default suites in this version
      enum: [
        'Ed25519Signature2020',
        'ecdsa-rdfc-2019', 'eddsa-rdfc-2022',
        'ecdsa-jcs-2019', 'eddsa-jcs-2022',
        'ecdsa-sd-2023', 'ecdsa-xi-2023', 'bbs-2023'
      ]
    }
  }
};

// supported status purposes in this version
const statusPurposes = ['activation', 'revocation', 'suspension'];

export const statusListConfig = {
  title: 'Status List Configuration',
  type: 'object',
  required: ['type', 'statusPurpose', 'zcapReferenceIds'],
  additionalProperties: false,
  properties: {
    type: {
      type: 'string',
      // supported types in this version
      enum: [
        'BitstringStatusList',
        // FIXME: consider removing `StatusList2021` support
        'StatusList2021',
        'TerseBitstringStatusList'
      ]
    },
    // base URL to use for new lists, defaults to `invocationTarget` from
    // zcap referred to by `createCredentialStatusList` reference ID
    baseUrl: {
      type: 'string'
    },
    // an ID value required to track index allocation and used with external
    // status list service; can be auto-generated, so not required
    indexAllocator: {
      // an ID (URL) referring to an index allocator
      type: 'string'
    },
    // note: scoped to `type`
    statusPurpose: {
      oneOf: [{
        type: 'string',
        enum: statusPurposes
      }, {
        // array usage triggers creation of multiple lists
        type: 'array',
        minItems: 1,
        items: {
          type: 'string',
          enum: statusPurposes
        },
        uniqueItems: true
      }]
    },
    // note: scoped to `type`; will be auto-populated with defaults so not
    // required
    options: {
      type: 'object',
      additionalProperties: false,
      properties: {
        blockCount: {
          type: 'integer',
          minimum: 1,
          maximum: MAX_BLOCK_COUNT
        },
        blockSize: {
          type: 'integer',
          minimum: 1,
          maximum: MAX_BLOCK_SIZE
        },
        // note: some list types will require a `listCount`, each having their
        // own different list count limits and defaults applied elsewhere; the
        // `MAX_LIST_COUNT` here is the maximum this software can keep track of
        listCount: {
          type: 'integer',
          minimum: 1,
          maximum: MAX_LIST_COUNT
        }
      }
    },
    // zcap reference IDs reference zcaps in the root config
    zcapReferenceIds: {
      type: 'object',
      required: ['createCredentialStatusList'],
      additionalProperties: false,
      properties: {
        createCredentialStatusList: {
          type: 'string'
        }
      }
    }
  }
};

export const statusListOptions = {
  title: 'Status List Options',
  type: 'array',
  minItems: MAX_STATUS_LIST_OPTIONS,
  items: statusListConfig
};

const vcdmType = {
  title: 'VCDM Type',
  oneOf: [{
    type: 'string'
  }, {
    type: 'array',
    items: {
      minItems: 1,
      items: {
        type: ['string']
      }
    }
  }]
};

const vcdmObject = {
  title: 'VCDM Object',
  type: 'object',
  additionalProperties: true,
  properties: {
    id: {
      type: 'string'
    },
    type: vcdmType
  }
};

const vcdmTypedObject = {
  ...vcdmObject,
  required: ['type']
};

const vcdmObjectOrReference = {
  title: 'VCDM Object or Reference',
  oneOf: [vcdmObject, {
    type: 'string'
  }]
};

const vcdmObjectSet = {
  title: 'VCDM Object Set',
  oneOf: [vcdmObject, {
    type: 'array',
    minItems: 1,
    items: vcdmObject
  }]
};

const vcdmObjectOrReferenceSet = {
  title: 'VCDM Object or Reference Set',
  oneOf: [vcdmObjectOrReference, {
    type: 'array',
    minItems: 1,
    items: vcdmObjectOrReference
  }]
};

const vcdmTypedObjectSet = {
  title: 'VCDM Typed Object Set',
  oneOf: [vcdmTypedObject, {
    type: 'array',
    minItems: 1,
    items: vcdmTypedObject
  }]
};

const languageObject = {
  type: 'object',
  required: ['@value'],
  additionalProperties: false,
  properties: {
    '@value': {
      type: 'string'
    },
    '@direction': {
      type: 'string'
    },
    '@language': {
      type: 'string'
    }
  }
};

const valueStringOrObject = {
  anyOf: [{type: 'string'}, languageObject]
};

const languageValue = {
  anyOf: [
    valueStringOrObject,
    {type: 'array', minItems: 1, items: valueStringOrObject}
  ]
};

export const issueCredentialBody = {
  title: 'Issue Credential',
  type: 'object',
  required: ['credential'],
  additionalProperties: false,
  properties: {
    options: {
      type: 'object',
      additionalProperties: false,
      properties: {
        credentialId: {
          type: 'string'
        },
        mandatoryPointers,
        extraInformation: {
          type: 'string'
        }
      }
    },
    credential: {
      type: 'object',
      additionalProperties: true,
      required: ['@context', 'type'],
      properties: {
        '@context': context,
        type: vcdmType,
        confidenceMethod: vcdmTypedObjectSet,
        credentialSchema: vcdmTypedObjectSet,
        credentialStatus: vcdmTypedObjectSet,
        credentialSubject: vcdmObjectOrReferenceSet,
        description: languageValue,
        evidence: vcdmTypedObjectSet,
        // `issuer` skipped, handled internally during issuance
        name: languageValue,
        proof: vcdmTypedObjectSet,
        refreshService: vcdmTypedObjectSet,
        relatedResource: vcdmObjectSet,
        renderMethod: vcdmTypedObjectSet,
        termsOfUse: vcdmTypedObjectSet,
        validFrom: {
          // FIXME: improve date validation
          type: 'string'
        },
        validUntil: {
          // FIXME: improve date validation
          type: 'string'
        },
        // VC 1.1 properties
        issuanceDate: {
          type: 'string'
        },
        expirationDate: {
          type: 'string'
        }
      }
    }
  }
};

function idOrObjectWithId() {
  return {
    title: 'identifier or an object with an id',
    anyOf: [
      schemas.identifier(),
      {
        type: 'object',
        required: ['id'],
        additionalProperties: true,
        properties: {id: schemas.identifier()}
      }
    ]
  };
}

export function vDL() {
  return {
    title: `Verifiable Driver's License`,
    type: 'object',
    required: [
      '@context',
      'credentialSubject',
      'issuer',
      'type'
    ],
    additionalProperties: false,
    properties: {
      '@context': {
        type: 'array',
        oneOf: [
          {const: [VC_CONTEXT_1, VDL_CONTEXT_1, VDL_AAMVA_CONTEXT_1]},
          {const: [VC_CONTEXT_2, VDL_CONTEXT_1, VDL_AAMVA_CONTEXT_1]}
        ]
      },
      id: {type: 'string'},
      issuer: idOrObjectWithId(),
      type: {
        const: ['VerifiableCredential', 'Iso18013DriversLicenseCredential']
      },
      name: {type: 'string'},
      image: {type: 'string'},
      description: {type: 'string'},
      credentialSubject: {
        type: 'object',
        required: ['type', 'driversLicense'],
        additionalProperties: false,
        properties: {
          id: {type: 'string'},
          type: {const: 'LicensedDriver'},
          driversLicense: {
            type: 'object',
            required: ['type'],
            additionalProperties: false,
            properties: {
              type: {const: 'Iso18013DriversLicense'},
              // base properties
              administrative_number: {type: 'string'},
              age_birth_year: {type: 'number'},
              age_in_years: {type: 'number'},
              age_over_18: {type: 'boolean'},
              age_over_21: {type: 'boolean'},
              age_over_25: {type: 'boolean'},
              age_over_62: {type: 'boolean'},
              age_over_65: {type: 'boolean'},
              birth_date: {type: 'string'},
              birth_place: {type: 'string'},
              document_number: {type: 'string'},
              driving_privileges: {type: 'array'},
              expiry_date: {type: 'string'},
              eye_colour: {type: 'string'},
              family_name: {type: 'string'},
              family_name_national_character: {type: 'string'},
              given_name: {type: 'string'},
              given_name_national_character: {type: 'string'},
              hair_colour: {type: 'string'},
              height: {type: 'number'},
              issue_date: {type: 'string'},
              issuing_authority: {type: 'string'},
              issuing_country: {type: 'string'},
              issuing_jurisdiction: {type: 'string'},
              nationality: {type: 'string'},
              portrait: {type: 'string'},
              portrait_capture_date: {type: 'string'},
              resident_address: {type: 'string'},
              resident_city: {type: 'string'},
              resident_country: {type: 'string'},
              resident_postal_code: {type: 'string'},
              resident_state: {type: 'string'},
              sex: {type: 'number'},
              signature_usual_mark: {type: 'string'},
              un_distinguishing_sign: {type: 'string'},
              weight: {type: 'number'},
              // aamva additions
              aamva_aka_family_name_v2: {type: 'string'},
              aamva_aka_given_name_v2: {type: 'string'},
              aamva_aka_suffix: {type: 'string'},
              aamva_cdl_indicator: {type: 'number'},
              aamva_dhs_compliance: {type: 'string'},
              aamva_dhs_compliance_text: {type: 'string'},
              aamva_dhs_temporary_lawful_status: {type: 'number'},
              aamva_domestic_driving_privileges: {type: 'object'},
              aamva_edl_credential: {type: 'number'},
              aamva_family_name_truncation: {type: 'string'},
              aamva_given_name_truncation: {type: 'string'},
              aamva_hazmat_endorsement_expiration_date: {type: 'string'},
              aamva_name_suffix: {type: 'string'},
              aamva_organ_donor: {type: 'number'},
              aamva_race_ethnicity: {type: 'string'},
              aamva_resident_county: {type: 'string'},
              aamva_sex: {type: 'number'},
              aamva_veteran: {type: 'number'},
              aamva_weight_range: {type: 'number'}
            }
          }
        }
      },
      // VCDM v2 (preferred)
      validFrom: {type: 'string'},
      validUntil: {type: 'string'},
      // VCDM v1 (deprecated)
      issuanceDate: {type: 'string'},
      expirationDate: {type: 'string'}
    }
  };
}

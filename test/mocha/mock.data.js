/*!
* Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
*/
'use strict';

const {config} = require('bedrock');

const mock = {};
module.exports = mock;

// mock product IDs and reverse lookup for service products
mock.productIdMap = new Map([
  // edv service
  ['edv', 'urn:uuid:dbd15f08-ff67-11eb-893b-10bf48838a41'],
  ['urn:uuid:dbd15f08-ff67-11eb-893b-10bf48838a41', 'edv'],
  // vc-issuer service
  ['vc-issuer', 'urn:uuid:66aad4d0-8ac1-11ec-856f-10bf48838a41'],
  ['urn:uuid:66aad4d0-8ac1-11ec-856f-10bf48838a41', 'vc-issuer'],
  // webkms service
  ['webkms', 'urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41'],
  ['urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41', 'webkms']
]);

mock.baseUrl = config.server.baseUri;

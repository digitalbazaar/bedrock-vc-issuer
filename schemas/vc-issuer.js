/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// const bedrock = require('bedrock');
// const {config} = bedrock;
// const {schemas} = require('bedrock-validation');

const instancesQuery = {
  title: 'Instances Query',
  type: 'object',
  additionalProperties: false,
  required: ['controller'],
  properties: {
    controller: {type: 'string'},
  }
};

const instancesCreate = {
  title: 'Instances Create',
  type: 'object',
  additionalProperties: false,
  required: ['controller', 'id', 'name'],
  properties: {
    // urn:uuid:a99bfceb-f888-44f2-9319-d51e36038062
    controller: {type: 'string'},
    // uuid
    id: {type: 'string'},
    // user supplied string, human readable name of the instance
    name: {type: 'string'},
  }
};

module.exports.instancesCreate = () => instancesCreate;
module.exports.instancesQuery = () => instancesQuery;

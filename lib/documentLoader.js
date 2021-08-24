/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {documentLoader: loader} = require('./configDocumentLoader');

const api = {};
module.exports = api;

api.documentLoader = loader;

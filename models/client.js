'use strict';
var mongoose = require('mongoose');
var BaseSchema = require('./baseSchema');

var clientSchema = new BaseSchema({
  name: { type: String, required: true, unique: true },
  clientId: { type: String, required: true, unique: true },
  clientSecret: { type: String, required: true, unique: true }
});

var Client = mongoose.model('Client', clientSchema);
module.exports = Client;

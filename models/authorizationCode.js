'use strict';
var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var BaseSchema = require('./baseSchema');

var authorizationCodeSchema = new BaseSchema({
  code: { type: String, required: true },
  redirectUri: { type: String },
  userId: { type: Schema.Types.ObjectId, ref: 'User' },
  clientId: { type: Schema.Types.ObjectId, ref: 'Client' }
});

var AuthorizationCode = mongoose.model('AuthorizationCode', authorizationCodeSchema);
module.exports = AuthorizationCode;

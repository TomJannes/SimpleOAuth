var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var accessTokenSchema = new Schema({
   token: { type: String, required: true },
   expirationDate: { type: Date },
   user: { type: Schema.Types.ObjectId, ref: 'User' },
   client: { type: Schema.Types.ObjectId, ref: 'Client' },
   grant: { type: Schema.Types.ObjectId, ref: 'GrantCode' },
   scope: { type: String }
});

var AccessToken = mongoose.model('AccessToken', accessTokenSchema);
module.exports = AccessToken;
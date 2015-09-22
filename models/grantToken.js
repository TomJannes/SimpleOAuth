var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var grantTokenSchema = new Schema({
   token: { type: String, required: true },
   user: { type: Schema.Types.ObjectId, ref: 'User' },
   client: { type: Schema.Types.ObjectId, ref: 'Client' },
});

var GrantToken = mongoose.model('GrantToken', grantTokenSchema);
module.exports = GrantToken;
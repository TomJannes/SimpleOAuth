var ObjectId = require('mongodb').ObjectId;

exports.id = '0005-create-client';

exports.up = function (done) {
  var coll = this.db.collection('client');
  coll.insert({ 
      _id: ObjectId('560d00da421db3b427f90308'), 
      name: 'testopenid', 
      clientId: 'ljvSib9e', 
      clientSecret: '0hsysJIyZgdInXIF580N', 
      createdAt: new Date(), 
      updatedAt: new Date()
  }, done);
};

exports.down = function (done) {
  var coll = this.db.collection('client');
  coll.remove({_id: ObjectId('560d00da421db3b427f90308')}, done);
};
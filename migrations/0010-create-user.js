var ObjectId = require('mongodb').ObjectId;

exports.id = '0010-create-user';

exports.up = function (done) {
  var coll = this.db.collection('user');
  coll.insert({ 
      _id: ObjectId('560d00da421db3b427f90309'), 
      fistname: 'firstname',
      lastname: 'lastname',
      username: 'test',
      password: 'test',
      clients: [ObjectId('560d00da421db3b427f90308')],
      createdAt: new Date(), 
      updatedAt: new Date()
  }, done);
};

exports.down = function (done) {
  var coll = this.db.collection('user');
  coll.remove({_id: ObjectId('560d00da421db3b427f90309')}, done);
};
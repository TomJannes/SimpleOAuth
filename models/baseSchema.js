var util = require('util');
var mongoose = require('mongoose');
var Schema = mongoose.Schema;

function BaseSchema() {
    Schema.apply(this, arguments);

    this.add({
        createdAt: Date,
        updatedAt: Date
    });
  
    this.virtual('id').get(function(){
        return this._id.toHexString();
    });

    this.set('toJSON', {
        virtuals: true
    });
    
    this.set('toObject', { 
        virtuals: true 
    });
    
    this.pre('save', function(next) {
        this.createdAt = new Date();
        next();
    });
    
    this.pre('update', function() {
        this.update({},{ $set: { updatedAt: new Date() } });
    });
}

util.inherits(BaseSchema, Schema);

//var baseSchema = new BaseSchema();
module.exports = BaseSchema;


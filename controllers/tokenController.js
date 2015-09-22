var db = require('../db').db();
var crypto = require('crypto');
var utils = require('../utils');

exports.getTokenInfo = function(req, res) {
    var accessToken = req.params.accessToken;
    if(!accessToken) return res.status(400).send('no token received');
    
    var accessTokenHash = crypto.createHash('sha1').update(accessToken).digest('hex');
        db.collection('accessTokens').findOne({token: accessTokenHash}, function (err, token) {
            utils.handleInternalServerError(err, res);
            if (!token) return res.status(401).send('token was not found in db');
            if (new Date() > token.expirationDate) {
                db.collection('accessTokens').remove({token: accessTokenHash}, function (err) { 
                    utils.handleInternalServerError(err, res);
                    return res.status(401).send('token is expired'); 
                });
            } else {
                db.collection('users').findOne({username: token.userId}, function (err, user) {
                    utils.handleInternalServerError(err, res);
                    if (!user) return res.status(401).send('no user found for token');
                    // no use of scopes for no
                    //var info = { scope: '*' }
                    //done(null, user, info);
                    //todo: implement scopes
                    token.user = user;
                    return res.json(token);
                });
            }
        })
};
var oauth2orize = require('oauth2orize');
var db = require('../db').db();
var crypto = require('crypto');
var utils = require("../utils");
var passport = require("passport");

// create OAuth 2.0 server
var server = oauth2orize.createServer();

//(De-)Serialization for clients
server.serializeClient(function(client, done) {
    return done(null, client.clientId);
});

server.deserializeClient(function(id, done) {
    db.collection('clients').find({clientId: id}, function(err, client) {
        if (err) return done(err);
        return done(null, client);
    });
});

//Implicit grant
server.grant(oauth2orize.grant.token(function (client, user, ares, done) {
    var token = utils.uid(256);
    var tokenHash = crypto.createHash('sha1').update(token).digest('hex');
    var expirationDate = new Date(new Date().getTime() + (3600 * 1000));
    
    db.collection('accessTokens').save({token: tokenHash, expirationDate: expirationDate, userId: user.username, clientId: client.clienId}, function(err) {
        if (err) return done(err);
        return done(null, token, {expires_in: expirationDate.toISOString()});
    });
}));

server.exchange(oauth2orize.exchange.clientCredentials(function(client, scope, done) {
    var token = utils.uid(256);
    var tokenHash = crypto.createHash('sha1').update(token).digest('hex');
    var expiresIn = 1800;
    var expirationDate = new Date(new Date().getTime() + (expiresIn * 1000));
 
    db.collection('accessTokens').save({token: tokenHash, expirationDate: expirationDate, clientId: client.clienId, scope: scope}, function(err) {
        if (err) return done(err);
        return done(null, token, {expires_in: expiresIn});
    });
}));

/*start test */
server.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
    //save code in the db
    var code = utils.uid(16);
    return done(null, code);
}));

server.exchange(oauth2orize.exchange.code(function(client, code, redirectURI, done) {
    //fetch code from the db & generate token
    var token = utils.uid(256);
    return done(null, token);
}));
/*end test*/

// user authorization endpoint
exports.performAuthorization = [
  function(req, res, next) {
    if (req.user) next();
    else res.redirect('/oauth/authorization');
  },
  server.authorization(function(clientId, redirectURI, done) {
    db.collection('clients').findOne({clientId: clientId}, function(err, client) {
      if (err) return done(err);
      // WARNING: For security purposes, it is highly advisable to check that
      // redirectURI provided by the client matches one registered with
      // the server. For simplicity, this example does not. You have
      // been warned.
      return done(null, client, redirectURI);
      //return done(null, client);
    });
  }),
  function(req, res, next) {
    server.decision({loadTransaction: false}, function(req, callback) {
                    callback(null, { allow: true });
                })(req, res, next);
  }
];

// user authorization endpoint
exports.performAuthorization2 = [
  function(req, res, next) {
    if (req.user) next();
    else res.redirect('/oauth/authorization2');
  },
  server.authorization(function(clientId, redirectURI, done) {
    db.collection('clients').findOne({clientId: clientId}, function(err, client) {
      if (err) return done(err);
      // WARNING: For security purposes, it is highly advisable to check that
      // redirectURI provided by the client matches one registered with
      // the server. For simplicity, this example does not. You have
      // been warned.
      return done(null, client, redirectURI);
      //return done(null, client);
    });
  }),
  function(req, res, next) {
    server.decision({loadTransaction: false}, function(req, callback) {
                    callback(null, { allow: true });
                })(req, res, next);
  }
];

exports.token = [
    passport.authenticate('clientPassword'),
    server.token(),
    server.errorHandler()
];

// user decision endpoint
exports.decision = [
  function(req, res, next) {
    if (req.user) next();
    else res.redirect('/oauth/authorization');
  },
  server.decision()
];

exports.performClientPasswordAuthorization = [
    passport.authenticate(['clientBasic', 'clientPassword'], { session: false }),
    server.token(),
    server.errorHandler()
]
var oauth2orize = require('oauth2orize');
var crypto = require('crypto');
var utils = require("../utils");
var passport = require("passport");
var Client = require('../models/client');
var GrantToken = require('../models/grantToken');
var AccessToken = require('../models/accessToken');

// create OAuth 2.0 server
var server = oauth2orize.createServer();

//(De-)Serialization for clients
server.serializeClient(function(client, done) {
    return done(null, client.clientId);
});

server.deserializeClient(function(id, done) {
    Client.findOne({clientId: id}, function(err, client){
      if (err) return done(err);
      return done(null, client);
    });
});

server.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
    GrantToken.findOne({
      $and: [
        { client: client }, 
        { user: user} 
      ]
    }, function(err, grant){
      if (err) return done(err);
      if(!grant){
        grant = new GrantToken({
            client: client,
            user: user,
            token: utils.uid(16)
        });
        grant.save(function(err) {
            done(err, err ? null : grant.token);
        });
      } else {
        done(null, grant.token);
      }
    });
}));

server.exchange(oauth2orize.exchange.code(function(client, code, redirectURI, done) {
  GrantToken.findOne({ token: code }, function(error, grant) {
    if (grant && grant.client == client.id) {
      var token = AccessToken({
        token: utils.uid(256),
        expirationDate: new Date((new Date()).getTime() + 60*60000),
        user: grant.user,
        client: grant.client,
        grant: grant,
        scope: grant.scope
      });
      token.save(function(error) {
        done(error, error ? null : token.token, null, error ? null : { token_type: 'standard' });
      });
    } else {
      done(error, false); 
    }
  });
}));

// user authorization endpoint
exports.performAuthorization = [
  function(req, res, next) {
    if (req.user) next();
    else res.redirect('/oauth/authorization?response_type=' + req.body.responseType + '&client_id=' + req.body.clientId + (req.body.redirectUri ? '&redirect_uri=' + req.body.redirectUri : ''));
  },
  server.authorization(function(clientId, redirectURI, done) {
    Client.findOne({clientId: clientId}, function(err, client){
      if (err) return done(err);
      // WARNING: For security purposes, it is highly advisable to check that
      // redirectURI provided by the client matches one registered with
      // the server. For simplicity, this example does not. You have
      // been warned.
      return done(null, client, redirectURI);
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
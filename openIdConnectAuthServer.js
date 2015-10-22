/**
 * Module dependencies.
 */
var oauth2orize = require('oauth2orize'),
  oauth2orize_ext = require('oauth2orize-openid'), // require extentions.
  passport = require('passport'),
  login = require('connect-ensure-login'),
  utils = require('./utils'),
  AuthorizationCode = require('./models/authorizationCode'),
  AccessToken = require('./models/accessToken'),
  RefreshToken = require('./models/refreshToken'),
  Client = require('./models/client'),
  User = require('./models/user'),
  jwt = require('jsonwebtoken'),
  utils = require('./utils'),
  config = require('config'),
  crypto = require('crypto'),
  Promise = require('bluebird'),
  fs = Promise.promisifyAll(require('fs')), //todo: move to startup + cache
  NotAllowedError = require('./errors/notAllowedError');

// create OAuth 2.0 server
var server = oauth2orize.createServer();

// Register serialialization and deserialization functions.
//
// When a client redirects a user to user authorization endpoint, an
// authorization transaction is initiated.  To complete the transaction, the
// user must authenticate and approve the authorization request.  Because this
// may involve multiple HTTP request/response exchanges, the transaction is
// stored in the session.
//
// An application must supply serialization functions, which determine how the
// client object is serialized into the session.  Typically this will be a
// simple matter of serializing the client's ID, and deserializing by finding
// the client by ID from the database.

server.serializeClient(function(client, done) {
  return done(null, client.id);
});

server.deserializeClient(function(id, done) {
  Client.findById(id, function(err, client) {
    if (err) {
      return done(err);
    }
    return done(null, client);
  });
});

// Register supported OpenID Connect 1.0 grant types.

// Implicit Flow

// id_token grant type.
server.grant(oauth2orize_ext.grant.idToken(function(client, user, done) {
  var id_token;
  // Do your lookup/token generation.
  // ... id_token =

  done(null, id_token);
}));

// 'id_token token' grant type.
server.grant(oauth2orize_ext.grant.idTokenToken(
  function(client, user, done) {

    var token;
    // Do your lookup/token generation.
    // ... token =

    done(null, token);
  },
  function(client, user, done) {
    var id_token;
    // Do your lookup/token generation.
    // ... id_token =
    done(null, id_token);
  }
));

// Hybrid Flow

// 'code id_token' grant type.
server.grant(oauth2orize_ext.grant.codeIdToken(
  function(client, redirect_uri, user, done) {
    var code;
    // Do your lookup/token generation.
    // ... code =

    done(null, code);
  },
  function(client, user, done) {
    //do i need lookups here?
    var lifetimeInMinutes = 60;
    var id_token = {
      "iss": config.get('issuer'),
      "sub": user.id,
      "aud": client.clientId,
      "exp": new Date((new Date()).getTime() + lifetimeInMinutes * 60000),
      "iat": new Date()
    }
    done(null, id_token);
  }
));

// 'code token' grant type.
server.grant(oauth2orize_ext.grant.codeToken(
  function(client, user, done) {
    var token;
    // Do your lookup/token generation.
    // ... id_token =
    done(null, token);
  },
  function(client, redirect_uri, user, done) {
    var code;
    // Do your lookup/token generation.
    // ... code =

    done(null, code);
  }
));

// 'code id_token token' grant type.
server.grant(oauth2orize_ext.grant.codeIdTokenToken(
  function(client, user, done) {
    // Do your lookup/token generation.
    //access_token
    //do we need to lookup the access token and reuse if one exists or always generate a new one????
    //createAccessToken(client.id, user.id, done)
  },
  function(client, redirect_uri, user, done) {
    //what should i do with the redirect url here?? find out (see comments further down, is needed for extra security check)
    //createAuthorizationCode(client.id, user.id, redirect_uri, done)
  },
  function(client, user, done) {
    //do we need validation of some sorts here?
    //createIdToken(client.clientId, user.userId, done);
  }
));


// Register supported Oauth 2.0 grant types.
//
// OAuth 2.0 specifies a framework that allows users to grant client
// applications limited access to their protected resources.  It does this
// through a process of the user granting access, and the client exchanging
// the grant for an access token.

function removeTokens(clientId, userId) {
  return AccessToken.removeAsync({
      userId: userId,
      clientId: clientId
    })
    .then(function() {
      return RefreshToken.removeAsync({
        userId: userId,
        clientId: clientId
      });
    });
}

function createRefreshToken(clientId, userId) {
  var refreshToken = utils.uid(32);
  return new RefreshToken({
    token: refreshToken,
    userId: userId,
    clientId: clientId,
    expiryDate: new Date((new Date()).getTime() + config.get('accesstoken_lifetime_in_minutes') * 60000)
  });
}

function createAccessToken(clientId, userId) {
  var accessToken = utils.uid(256);
  return new AccessToken({
    token: accessToken,
    userId: userId,
    clientId: clientId,
    expiryDate: new Date((new Date()).getTime() + config.get('accesstoken_lifetime_in_minutes') * 60000)
  });
}

function generateTokenOptions(clientId, userId) {
  return {
    algorithm: 'RS256',
    expiresIn: config.get('accesstoken_lifetime_in_minutes') + 'm',
    audience: clientId,
    subject: userId,
    issuer: config.get('issuer')
  };
}

function createAuthorizationCode(clientId, userId, redirectUri) {
  var code = crypto.randomBytes(16).toString('hex');
  return new AuthorizationCode({
    code: code,
    redirectUri: redirectUri,
    userId: userId,
    clientId: clientId
  });
}

// Grant authorization codes.  The callback takes the `client` requesting
// authorization, the `redirectURI` (which is used as a verifier in the
// subsequent exchange), the authenticated `user` granting access, and
// their response, which contains approved scope, duration, etc. as parsed by
// the application.  The application issues a code, which is bound to these
// values, and will be exchanged for an access token.
server.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
  AuthorizationCode.findOneAsync({
      userId: user.id,
      clientId: client.id
    })
    .then(function(authCode) {
      if (!authCode) {
        var authorizationCode = createAuthorizationCode(client.id, user.id, redirectURI);
        return authorizationCode.saveAsync();
      }
      else {
        return [authCode];
      }
    })
    .spread(function(authCode) {
      return [authCode.code];
    })
    .catch(function(err) {
      return [err];
    })
    .nodeify(done, {
      spread: true
    });
}));

// Grant implicit authorization.  The callback takes the `client` requesting
// authorization, the authenticated `user` granting access, and
// their response, which contains approved scope, duration, etc. as parsed by
// the application.  The application issues a token, which is bound to these
// values.
server.grant(oauth2orize.grant.token(function(client, user, ares, done) {
  var token = createAccessToken(client.id, user.id);
  token.save(function(err) {
    if (err) {
      return done(err);
    }
    done(null, token);
  });
}));

// Exchange authorization codes for access tokens.  The callback accepts the
// `client`, which is exchanging `code` and any `redirectURI` from the
// authorization request for verification.  If these values are validated, the
// application issues an access token on behalf of the user who authorized the
// code.
server.exchange(oauth2orize.exchange.code(function(client, code, redirectURI, done) {
  AuthorizationCode.findOneAsync({
      code: code
    })
    .bind({})
    .then(function(authCode) {
      this.authCode = authCode;
      if (!authCode.clientId.equals(client.id)) {
        throw new NotAllowedError('auth code client id different from current clients id');
      }
      if (redirectURI !== authCode.redirectUri) {
        throw new NotAllowedError('redirectURI not matching auth code redirectURI');
      }

      return removeTokens(this.authCode.clientId, this.authCode.userId);
    })
    .then(function() {
      var newRefreshToken = createRefreshToken(this.authCode.clientId, this.authCode.userId);
      return newRefreshToken.saveAsync();
    })
    .spread(function(savedRefreshToken) {
      this.savedRefreshToken = savedRefreshToken;
      var newAccessToken = createAccessToken(this.authCode.clientId, this.authCode.userId)
      return newAccessToken.saveAsync();
    })
    .spread(function(savedAccessToken) {
      this.savedAccessToken = savedAccessToken;
      return fs.readFileAsync('private_key.pem', 'utf8');
    })
    .then(function(data) {
      var token = jwt.sign({
        foo: 'bar'
      }, data, generateTokenOptions(client.clientId, this.authCode.userId));
      return [this.savedAccessToken.token, this.savedRefreshToken.token, {
        id_token: token,
        expires_in: this.savedAccessToken.expiryDate
      }];
    })
    .catch(function(err) {
      return [err];
    })
    .nodeify(done, {
      spread: true
    });
}));

server.exchange(oauth2orize.exchange.refreshToken(function(client, refreshToken, scope, done) {
  RefreshToken.findOneAsync({
      token: refreshToken
    })
    .bind({})
    .then(function(dbRefreshToken) {
      this.dbRefreshToken = dbRefreshToken;
      if (!dbRefreshToken) {
        throw new NotAllowedError('refresh token was not found');
      }
      if (!dbRefreshToken.clientId.equals(client.id)) {
        throw new NotAllowedError('refresh token client id different from current clients id');
      }
      return User.findByIdAsync(dbRefreshToken.userId);
    })
    .then(function(user) {
      if (!user) {
        throw new NotAllowedError('refresh token user was not found');
      }
      this.user = user;
      return removeTokens(client.id, this.user.id);
    })
    .then(function() {
      var newRefreshToken = createRefreshToken(this.dbRefreshToken.clientId, this.user.id);
      return newRefreshToken.saveAsync();
    })
    .spread(function(savedRefreshToken) {
      this.savedRefreshToken = savedRefreshToken;
      var newAccessToken = createAccessToken(savedRefreshToken.clientId, savedRefreshToken.userId);
      return newAccessToken.saveAsync();
    })
    .spread(function(savedAccessToken) {
      return [savedAccessToken.token, this.savedRefreshToken.token, {
        expires_in: savedAccessToken.expiryDate
      }];
    })
    .catch(NotAllowedError, function(err) {
      console.log(err);
      return [false];
    })
    .catch(function(err) {
      console.log(err);
      return [err];
    })
    .nodeify(done, {
      spread: true
    });
}));

// Exchange user id and password for access tokens.  The callback accepts the
// `client`, which is exchanging the user's name and password from the
// authorization request for verification. If these values are validated, the
// application issues an access token on behalf of the user who authorized the code.

server.exchange(oauth2orize.exchange.password(function(client, username, password, scope, done) {
  Client.findOneAsync({
      clientId: client.clientId
    })
    .bind({})
    .then(function(dbClient) {
      if (!dbClient) {
        return [false];
      }
      if (dbClient.clientSecret !== client.clientSecret) {
        return [false];
      }
      return User.findOneAsync({
        username: username
      });
    })
    .then(function(user) {
      if (!user) {
        return [false];
      }
      if (password !== user.password) {
        return [false];
      }
      var newAccessToken = createAccessToken(client.clientId, user.userId)
      return newAccessToken.saveAsync();
    })
    .spread(function(savedAccessToken) {
      return [savedAccessToken.token];
    })
    .catch(function(err) {
      return [err];
    })
    .nodeify(done, {
      spread: true
    });
}));

// Exchange the client id and password/secret for an access token.  The callback accepts the
// `client`, which is exchanging the client's id and password/secret from the
// authorization request for verification. If these values are validated, the
// application issues an access token on behalf of the client who authorized the code.

server.exchange(oauth2orize.exchange.clientCredentials(function(client, scope, done) {
  Client.findOneAsync({
      clientId: client.clientId
    })
    .bind({})
    .then(function(dbClient) {
      if (!dbClient) {
        return [false];
      }
      if (dbClient.clientSecret !== client.clientSecret) {
        return [false];
      }
      var newAccessToken = createAccessToken(client.clientId, null)
      return newAccessToken.saveAsync();
    })
    .spread(function(savedAccessToken) {
      return [savedAccessToken.token];
    })
    .catch(function(err) {
      return [err];
    })
    .nodeify(done, {
      spread: true
    });
}));

// user authorization endpoint
//
// `authorization` middleware accepts a `validate` callback which is
// responsible for validating the client making the authorization request.  In
// doing so, is recommended that the `redirectURI` be checked against a
// registered value, although security requirements may vary accross
// implementations.  Once validated, the `done` callback must be invoked with
// a `client` instance, as well as the `redirectURI` to which the user will be
// redirected after an authorization decision is obtained.
//
// This middleware simply initializes a new authorization transaction.  It is
// the application's responsibility to authenticate the user and render a dialog
// to obtain their approval (displaying details about the client requesting
// authorization).  We accomplish that here by routing through `ensureLoggedIn()`
// first, and rendering the `dialog` view. 

exports.authorization = [
  login.ensureLoggedIn(),
  server.authorization(function(clientId, redirectURI, done) {
    Client.findOne({
      clientId: clientId
    }, function(err, client) {
      if (err) {
        return done(err);
      }
      // WARNING: For security purposes, it is highly advisable to check that
      //          redirectURI provided by the client matches one registered with
      //          the server.  For simplicity, this example does not.  You have
      //          been warned.
      return done(null, client, redirectURI);
    });
  }),
  function(req, res, next) {
    if (req.query.prompt !== 'none') return next();
    // When using "prompt=none", redirect back immediately
    server.decision({
      loadTransaction: false
    }, function parse(sreq, done) {
      if (!sreq.user) return done(null, {
        allow: false
      });
      done();
    })(req, res, next);
  },
  function(req, res) {
    res.render('dialog', {
      transactionID: req.oauth2.transactionID,
      user: req.user,
      client: req.oauth2.client
    });
  }
]

// user decision endpoint
//
// `decision` middleware processes a user's decision to allow or deny access
// requested by a client application.  Based on the grant type requested by the
// client, the above grant middleware configured above will be invoked to send
// a response.

exports.decision = [
  login.ensureLoggedIn(),
  server.decision()
]


// token endpoint
//
// `token` middleware handles client requests to exchange authorization grants
// for access tokens.  Based on the grant type being exchanged, the above
// exchange middleware will be invoked to handle the request.  Clients must
// authenticate when making requests to this endpoint.

exports.token = [
  passport.authenticate(['basic', 'oauth2-client-password'], {
    session: false
  }),
  server.token(),
  server.errorHandler()
]
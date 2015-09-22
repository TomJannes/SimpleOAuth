/**
* Module dependencies.
*/
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var BasicStrategy = require('passport-http').BasicStrategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
var BearerStrategy = require('passport-http-bearer').Strategy;
var db = require('./db').db();
var bcrypt = require('bcrypt');
var crypto = require('crypto');


/**
* LocalStrategy
*/
passport.use(new LocalStrategy(
    function(username, password, done) {
        db.collection('users').findOne({username: username}, function(err, user) {
            if (err) { return done(err); }
            if (!user) { return done(null, false); }
            bcrypt.compare(password, user.password, function (err, res) {
                if(err) return done(err);
                if (!res) return done(null, false);
                return done(null, user);
            });
        });
    }
));

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    done(null, user);
});


/**
 * These strategies are used to authenticate registered OAuth clients.
 * The authentication data may be delivered using the basic authentication scheme (recommended)
 * or the client strategy, which means that the authentication data is in the body of the request.
 */
passport.use("clientBasic", new BasicStrategy(
    function (clientId, clientSecret, done) {
        db.collection('clients').findOne({clientId: clientId}, function (err, client) {
            if (err) return done(err);
            if (!client) return done(null, false);

            if (client.clientSecret == clientSecret) return done(null, client);
            else return done(null, false);
        });
    }
));

passport.use("clientPassword", new ClientPasswordStrategy(
    function (clientId, clientSecret, done) {
        db.collection('clients').findOne({clientId: clientId}, function (err, client) {
            if (err) return done(err);
            if (!client) return done(null, false);

            if (client.clientSecret == clientSecret) return done(null, client);
            else return done(null, false);
        });
    }
));

/**
 * This strategy is used to authenticate users based on an access token (aka a
 * bearer token).
 */
passport.use("accessToken", new BearerStrategy(
    function (accessToken, done) {
        var accessTokenHash = crypto.createHash('sha1').update(accessToken).digest('hex');
        db.collection('accessTokens').findOne({token: accessTokenHash}, function (err, token) {
            if (err) return done(err);
            if (!token) return done(null, false);
            if (new Date() > token.expirationDate) {
                db.collection('accessTokens').remove({token: accessTokenHash}, function (err) { done(err) });
            } else {
                db.collection('users').findOne({username: token.userId}, function (err, user) {
                    if (err) return done(err);
                    if (!user) return done(null, false);
                    // no use of scopes for no
                    var info = { scope: '*' };
                    done(null, user, info);
                });
            }
        });
    }
));
//todo: add new bearer strategy: clientAccessToken



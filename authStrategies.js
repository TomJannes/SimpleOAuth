/**
* Module dependencies.
*/
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
var BearerStrategy = require('passport-http-bearer').Strategy;
var bcrypt = require('bcrypt');
var crypto = require('crypto');

var User = require('./models/user');
var Client = require('./models/client');
var AccessToken = require('./models/accessToken')


/**
* LocalStrategy
*/
passport.use(new LocalStrategy(
    function(username, password, done) {
        User.findOne({username: username}, function(err, user){
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
    //todo: implement with id
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    //todo: implement with id
    done(null, user);
});

passport.use('clientPassword', new ClientPasswordStrategy(
    function (clientId, clientSecret, done) {
        Client.findOne({clientId: clientId}, function(err, client){
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
passport.use('accessToken', new BearerStrategy(
    function (accessToken, done) {
        //var accessTokenHash = crypto.createHash('sha1').update(accessToken).digest('hex');
        AccessToken.findOne({token: accessToken}, function(err, token){
            if (err) return done(err);
            if (!token) return done(null, false);
            if (new Date() > token.expirationDate) {
                AccessToken.remove({token: token}, function (err) { done(err) });
            } else {
                User.findById(token.user, function (err, user) {
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
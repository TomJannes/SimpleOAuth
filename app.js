//Module dependencies
var express = require('express');
var http = require('http');
var passport = require('passport');
var session = require('express-session');
var bodyParser = require('body-parser');
var expressValidator = require('express-validator');
var logger = require('morgan');
var mongoose = require('mongoose');
var config = require('config');
var Promise = require('bluebird');
/*require("./authStrategies");
var registrationController = require('./controllers/registrationController');
var loginController = require('./controllers/loginController');
var authorizationController = require('./controllers/authorizationController');*/
var profileController = require('./controllers/profileController');

var site = require('./controllers/siteController');
var oauth2 = require('./openIdConnectAuthServer');

Promise.promisifyAll(mongoose.Model);
Promise.promisifyAll(mongoose.Model.prototype);
Promise.promisifyAll(mongoose.Query.prototype);

mongoose.connect(config.get('connectionstring'));

// Express configuration
var app = express();
app.set('views', __dirname + '/views');
app.set('view engine', 'jade');
app.use(bodyParser());
app.use(expressValidator());
app.use(session({ secret: 'keyboard cat1'}));
app.use(logger('dev'));

app.use(passport.initialize());
app.use(passport.session());

require('./openIdConnectAuthStrategies');

app.get('/', site.index);
app.get('/userregistration', site.registerUserForm);
app.post('/userregistration', site.registerUser);
app.get('/clientregistration', site.registerClientForm);
app.post('/clientregistration', site.registerClient);

app.get('/login', site.loginForm);
app.post('/login', site.login);
app.get('/logout', site.logout);
app.get('/account', site.account);

app.get('/dialog/authorize', oauth2.authorization);
app.post('/dialog/authorize/decision', oauth2.decision);
app.post('/oauth/token', oauth2.token);

app.get('/oauth/profile', passport.authenticate('bearer'), profileController.getProfile);

//implement when bearer is ok
/*app.get('/api/userinfo', user.info);
app.get('/api/clientinfo', client.info);*/

/*app.get('/client/registration', registrationController.showClientRegistration);
app.post('/client/registration', registrationController.registerClient);

app.get('/registration', registrationController.showUserRegistration);
app.post('/registration', registrationController.registerUser);

app.get('/oauth/authorization', loginController.showLogin);
app.post('/oauth/authorization',
    //calling custom callback because we can not have dynamic failureredirects otherwise
    function(req, res, next) {
        passport.authenticate('local', function(err, user, info) {
            if (err) { return next(err); }
            if (!user) { return res.redirect('/oauth/authorization?response_type=' + req.body.responseType + '&client_id=' + req.body.clientId + (req.body.redirectUri ? '&redirect_uri=' + req.body.redirectUri : '')); }
            req.logIn(user, function(err) {
                return next(err);
            });
        })(req, res, next);
    },
    loginController.performLogin);

app.get('/authorization', authorizationController.performAuthorization);
app.post('/oauth/token', authorizationController.token);

app.get('/profile', passport.authenticate('accessToken'), profileController.getProfile);*/

//Start
if(config.has('server.port')){
  process.env.PORT = config.get('server.port');
}
if(config.has('server.ip')){
  process.env.IP = config.get('server.ip');
}
http.createServer(app).listen(process.env.PORT || 3000, process.env.IP || "0.0.0.0");

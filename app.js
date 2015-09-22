//Module dependencies
var express = require('express');
var http = require('http');
var passport = require('passport');
var session = require('express-session');
var bodyParser = require('body-parser');
var expressValidator = require('express-validator');
var logger = require('morgan');

require("./authStrategies");
var tokenController = require('./controllers/tokenController');
var registrationController = require('./controllers/registrationController');
var loginController = require('./controllers/loginController');
var authorizationController = require('./controllers/authorizationController');

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

app.get('/client/registration', registrationController.showClientRegistration);
app.post('/client/registration', registrationController.registerClient);

app.get('/registration', registrationController.showUserRegistration);
app.post('/registration', registrationController.registerUser);

app.get('/oauth/authorization', loginController.showLogin);
app.post('/oauth/authorization', passport.authenticate(['local'], { failureRedirect: '/oauth/authorization' }), loginController.performLogin);

app.get('/oauth/authorization2', loginController.showLogin2);
//what about redirect url?
app.post('/oauth/authorization2', passport.authenticate(['local'], { failureRedirect: '/oauth/authorization2' }), loginController.performLogin2);
app.get('/authorization2', authorizationController.performAuthorization2);
app.post('/oauth/token2', authorizationController.token);

app.post('/oauth/token', authorizationController.performClientPasswordAuthorization);

app.get('/authorization', authorizationController.performAuthorization);
app.post('/decision', authorizationController.decision);

app.get('/profile', passport.authenticate('accessToken', { session: false }), function (req, res) {
    res.json(req.user);
});

app.get('/tokeninfo/:accessToken', tokenController.getTokenInfo);

//Start
http.createServer(app).listen(process.env.PORT || 3000, process.env.IP || "0.0.0.0");

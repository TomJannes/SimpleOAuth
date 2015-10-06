var passport = require('passport')
  , login = require('connect-ensure-login')
  , User = require('../models/user')
  , Client = require('../models/client')
  , utils = require('../utils');


exports.index = function(req, res) {
  res.send('OAuth 2.0 Server');
};

exports.loginForm = function(req, res) {
  res.render('login');
};

exports.login = passport.authenticate('local', { successReturnToOrRedirect: '/', failureRedirect: '/login' });

exports.logout = function(req, res) {
  req.logout();
  res.redirect('/');
};

exports.registerUserForm = function(req, res) {
  res.render('userRegistration');
};

exports.registerUser = function(req, res) {
  var newUser = new User({
    firstname: req.body.firstname,
    lastname: req.body.lastname,
    username: req.body.username,
    password: req.body.password
  });
  newUser.save(function(err){
    if(err){
      res.send(err);
    } else {
      res.send('ok');
    }
    
  });
};

exports.registerClientForm = function(req, res) {
  res.render('clientRegistration');
};

exports.registerClient = function(req, res) {
  var clientId = utils.uid(8);
  var clientSecret = utils.uid(20);
  var newClient = new Client({
    name: req.body.name,
    clientId: clientId,
    clientSecret: clientSecret
  });
  newClient.save(function(err){
    if(err){
      res.send(err);
    } else {
      res.send('ok');
    }
    
  });
};


exports.account = [
  login.ensureLoggedIn(),
  function(req, res) {
    res.render('account', { user: req.user });
  }
];
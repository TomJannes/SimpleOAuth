var utils = require("../utils");
var bcrypt = require('bcrypt');
var utils = require('../utils');

var User = require('../models/user');
var Client = require('../models/client');
    
exports.showClientRegistration = function(req, res) { res.render('clientRegistration') };
exports.showUserRegistration = function(req, res) { res.render('userRegistration') };

exports.registerUser = function(req, res) {
    //todo: perhaps we can do this in mongoose???
    req.checkBody('username', 'No valid username is given').notEmpty().len(3, 40);
    req.checkBody('password', 'No valid password is given').notEmpty().len(6, 50);

    //wtf is this validationerrors? check online
    var errors = req.validationErrors();
    if (errors) return res.send(errors, 400);

    var username = req.body['username'];
    var password = req.body['password'];
    User.findOne({username: username}, function(err, user){
        utils.handleInternalServerError(err, res);
        if (user) return res.status(422).send("Username is already taken");
        
        bcrypt.hash(password, 11, function (err, hash) {
            utils.handleInternalServerError(err, res);
            
            var newUser = User({
                username: username,
                password: hash 
            });
            newUser.save(function(err){
                utils.handleInternalServerError(err, res);
                return res.send({username: username}, 201);
            });
        });
    });
};

exports.registerClient = function(req, res) {
    req.checkBody('name', 'No valid name is given').notEmpty().len(3, 40);

    var errors = req.validationErrors();
    if (errors) return res.send(errors, 400);
    
    var name = req.body['name'];
    var clientId = utils.uid(8);
    var clientSecret = utils.uid(20);
    
    Client.findOne({name: name}, function(err, client){
        utils.handleInternalServerError(err, res);
        if(client) {
            return res.send("Name is already taken", 422);
        } 
        var newClient = Client({
            name: name,
            clientId: clientId,
            clientSecret: clientSecret
        });
        newClient.save(function(err){
            utils.handleInternalServerError(err, res);
        });
        return res.send({name: name, clientId: clientId, clientSecret: clientSecret}, 201);
    });
};


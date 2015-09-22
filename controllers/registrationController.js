var db = require('../db').db();
var utils = require("../utils");
var bcrypt = require('bcrypt');
var utils = require('../utils');
    
exports.showClientRegistration = function(req, res) { res.render('clientRegistration') };
exports.showUserRegistration = function(req, res) { res.render('userRegistration') };

exports.registerUser = function(req, res) {
    req.checkBody('username', 'No valid username is given').notEmpty().len(3, 40);
    req.checkBody('password', 'No valid password is given').notEmpty().len(6, 50);

    var errors = req.validationErrors();
    if (errors) return res.send(errors, 400);

    var username = req.body['username'];
    var password = req.body['password'];
    db.collection('users').findOne({username: username}, function (err, user) {
        utils.handleInternalServerError(err, res);
        if (user) return res.status(422).send("Username is already taken");

        bcrypt.hash(password, 11, function (err, hash) {
            utils.handleInternalServerError(err, res);
            db.collection('users').save({username: username, password: hash}, function (err) {
                utils.handleInternalServerError(err, res);
                return res.send({username: username}, 201);
            });
        });
    });
};

exports.registerClient = function(req, res) {
    req.checkBody('name', 'No valid name is given').notEmpty().len(3, 40);

    var errors = req.validationErrors();
    if (errors) {
        res.send(errors, 400);
    } else {
        var name = req.body['name'];
        var clientId = utils.uid(8);
        var clientSecret = utils.uid(20);

        db.collection('clients').findOne({name: name}, function (err, client) {
            utils.handleInternalServerError(err, res);
            if(client) {
                res.send("Name is already taken", 422);
            } else {
                db.collection('clients').save({name: name, clientId: clientId, clientSecret: clientSecret}, function (err) {
                    utils.handleInternalServerError(err, res);
                    res.send({name: name, clientId: clientId, clientSecret: clientSecret}, 201);
                });
            }
        });
    }
};


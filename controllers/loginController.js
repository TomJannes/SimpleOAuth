exports.showLogin = function(req, res) { 
    res.render('login', {clientId : req.query.client_id, redirectUri: req.query.redirect_uri, responseType: req.query.response_type});
};

exports.performLogin = function(req, res) {
    //It is not essential for the flow to redirect here, it would also be possible to call this directly
    res.redirect('/authorization?response_type=' + req.body.responseType + '&client_id=' + req.body.clientId + (req.body.redirectUri ? '&redirect_uri=' + req.body.redirectUri : ''));
};
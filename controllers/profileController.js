exports.getProfile = function(req, res) { 
    return res.json({
        sub: req.user.id,
        name: req.user.firstname + ' ' + req.user.lastname,
        given_name: req.user.firstname,
        family_name: req.user.lastname,
        email: req.user.email,
        language: req.user.language
    });
};
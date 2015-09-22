exports.getProfile = function(req, res) { 
    return res.json(req.user);
};
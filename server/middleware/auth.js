const {User} = require('../models/user.js');

let auth = (req,res,next) => {
    let token = req.cookies.auth;

    User.findByToken(token, (err, user)=>{
        if(err || !user) return res.status(401).send('Not Authorized');
        req.token = token;
        next();
    });
};

module.exports = {auth};
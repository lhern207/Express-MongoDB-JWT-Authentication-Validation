const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt =  require('jsonwebtoken');
const SALT_I = 10;

const userSchema = mongoose.Schema({
    email: {
        type: String,
        required: true,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    token: {
        type: String
    }
});

userSchema.pre('save', function(next){
    var user = this;
    if(user.isModified('password')){
        bcrypt.genSalt(SALT_I, function(err,salt){
            if(err){
                return next(err);
            }
            bcrypt.hash(user.password, salt, function(err,hash){
                if(err){
                    return next(err);
                }
                user.password = hash;
                next();
            });
        });
    }
    else{
        next();
    }
});

userSchema.methods.comparePassword = function(candidatePassword, cb){

    bcrypt.compare(candidatePassword, this.password, function(err, isMatch){
        if(err){
            throw cb(err);
        }
        cb(null, isMatch);
    });
};

userSchema.methods.generateToken = function(cb){
    var user = this;
    var token = jwt.sign(user._id.toHexString(), 'supersecret');

    user.token = token;
    user.save(function(err,user){
        if(err) {
            cb(err);
        }
        else{
            cb(null, user);
        }
    });
};

userSchema.statics.findByToken = function(token, cb){
    //This 'User' is not an instance of the schema. But rather, the schema object itself.
    //That's why we define findByToken inside statics.
    const User = this;
    jwt.verify(token, 'supersecret', function(err, decoded){
        if(err) return cb(err);
        User.findOne({_id:decoded, token:token}, function(err,user){
            //This 'user' is a document instance returned by findOne()
            if(err) return cb(err);
            cb(null, user);
        });
    });
}

const User = mongoose.model('User', userSchema);

module.exports = {User};
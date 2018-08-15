const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const {User} = require('./models/user.js');
const {auth} = require('./middleware/auth.js');

const app = express();
const db_url = 'mongodb://localhost:27017/auth';
mongoose.Promise = global.Promise;
mongoose.connect(process.env.MONGODB_URI || db_url);

app.use(bodyParser.json());
app.use(cookieParser());

app.post('/api/user', (req,res)=> {
    const user = new User({
        email: req.body.email,
        password: req.body.password
    });

    user.save((err,doc)=>{
        if(err){
            res.status(400).send(err);
        }
        res.status(200).send(doc);
    });
});

app.post('/api/user/login', (req,res)=>{
    User.findOne({'email':req.body.email}, (err,user)=>{
        if(err){
            res.status(400).send(err);
        }
        else if(!user){
            res.json({message: 'Auth failed, user not found'});
        }
        else{
            user.comparePassword(req.body.password, (err,isMatch)=>{
                if(err) {
                    throw err;
                }
                else if(!isMatch){
                    res.status(400).json({message:"Wrong password"});
                }
                else{
                    user.generateToken((err, user)=>{
                        if(err){
                            res.status(400).send(err);
                        }
                        else{
                            res.cookie('auth', user.token).send('ok');
                        }
                    });
                }
            });
        }
    });
});

app.get('/api/user/profile', auth, (req,res)=>{
    res.status(200).send(req.token);
});

const port = process.env.PORT || 3001;

app.listen(port, ()=>{
    console.log(`Started on port ${port}`);
});
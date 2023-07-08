
const User = require('./models/user.models');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const app = express();
const dotenv = require('dotenv').config();


app.use(cors());
app.use(express.json()); 


mongoose.connect(process.env.MONGO_URI)
.then(()=> {console.log('Server connected to MongoDB ✔')})
.catch((err)=>{console.log(err)})

// REGISTER - ADD ACCOUNT IN THE DATABASE
app.post('/api/register', async (req,res)=> {
    try {
        const encryptedPassword = await bcrypt.hash(req.body.password, 10);
        const user = await User.create({
            name: req.body.name,
            email: req.body.email,
            password: encryptedPassword
        })
        res.json({ status : 'ok' })
    } catch (error) {
        console.log(error);
        res.json({ status : 'error', error : 'A user with this email address already exist' })
    }
});

// LOGIN - CHECK IF ACCOUNT IS IN THE DATABASE 
app.post('/api/login', async (req,res)=> {
    try {
        const user = await User.findOne({
            email : req.body.email,
        })

        const isPasswordValid = await bcrypt.compare(req.body.password, user.password);

        if (user && isPasswordValid) {

            const token = jwt. sign(
                {
                    name : req.body.name,
                    email : req.body.email
                }, process.env.SECRET_KEY
            )

            return res.json({ status : 'ok', user : token });
        }
        else {
            return res.json({ status : 'error', user : false });
        }

    } catch (error) {
        res.json({ status : 'error', error : `${error}`})
    }
});

// JWT AUTHENTICATION - Verify token to login
app.get('/api/quote', async (req,res)=> {
    try {
        const token = req.headers['x-access-token'];
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        const email = decoded.email;


        const user = await User.findOne({ email : email });
        return res.json({ status : 'ok', quote: user.quote, name : user.name });
    } catch (error) {
        res.json({ status : 'error', error : `${error}`})
    }
});

// JWT AUTHENTICATION - Verify token to get and update quote
app.post('/api/quote', async (req,res)=> {
    try {
        const token = req.headers['x-access-token'];
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        const email = decoded.email;


        const user = await User.updateOne({ email : email, }, { $set : { quote: req.body.quote }});
        return res.json({ status : 'ok', name : decoded.name })
    } catch (error) {
        res.json({ status : 'error', error : `${error}`})
    }
});

const port = process.env.PORT;
app.listen(port, () => console.log(`Server running at port ${port} ✔`));
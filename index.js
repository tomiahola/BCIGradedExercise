const express = require('express')
const app = express()
const port = 3000
const passport = require('passport');
const BasicStrategy = require('passport-http').BasicStrategy;
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const upload = multer({dest: 'uploads/'});

app.use(bodyParser.json());

let userDb = [];
let postingDb = [];

passport.use(new BasicStrategy(
    (username, password, done) => {
        console.log('Basic strategy params, username ' + username + " , password " + password);
        
        //Credential check
        // search userDb for matching user
        
        const searchResult = userDb.find(user => {
            if(user.username === username) {
                if(bcrypt.compareSync(password, user.password)) {
                    return true;
                }
            }
            return false;
        })
        if(searchResult != undefined){
            done(null, searchResult); //successfully authenticated  
        } else {
            done(null, false); // no credential match
        }       
    }
));


/*This route will receive data structure
    {
        "username": "foo",
        "password": "bar",
        "email": "foo@bar.com"
    }
*/
app.post('/users', (req, res) => {

    console.log("original password: " + req.body.password);
    const salt = bcrypt.genSaltSync(6);
    console.log("salt: " + salt);
    const hashedPassword = bcrypt.hashSync(req.body.password, salt);
    console.log("hashed password: " + hashedPassword);

    const newUser = {
        id: uuidv4(),
        username: req.body.username,
        name: req.body.name,
        password: hashedPassword,
        email: req.body.email,
        dateOfBirth: req.body.dateOfBirth,
        address: req.body.address
    }

    userDb.push(newUser); // store the new user into DB
    res.sendStatus(201);
})

/** JWT implementation below */

const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwtSecretKey = "mySecretKey"
const secrets = require('./secrets.json')

const options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    //secretOrKey: jwtSecretKey
    secretOrKey: secrets.jwtSignKey,
    passReqToCallback: true
};

passport.use(new JwtStrategy(options, (req, payload, done) => {
    const currentUser = userDb.find(user => user.username == payload.user);
    console.log('user.username: ',userDb.find(user => user.username));
    console.log('payload: ', payload);
    console.log('current user: ', currentUser);

    if(currentUser) {
        req.user = currentUser;
        done(null, currentUser);
    } else {
        done(null, false);

    }
}));

app.post('/login', passport.authenticate('basic', {session: false}),  (req, res, next) => {

    // Create a JWT for the client

    const token = jwt.sign({user: req.user.username}, secrets.jwtSignKey);

    // Send the JWT to the client
    res.json({ token :token });

})

app.post('/postings',upload.array('photos', 4), passport.authenticate('jwt', {session: false}), (req, res) => {

    var d = new Date()
    var date = d.getFullYear() + "-" + ( d.getMonth() + 1 ) + "-" + d.getDate()


    const newPosting = {
        id: uuidv4(),
        title: req.body.title,
        description: req.body.description,
        category: req.body.category,
        askingPrice: req.body.askingPrice,
        dateOfPosting: date,
        locationCountry: req.body.locationCountry,
        locationCity: req.body.locationCity,
        locationStreet: req.body.locationStreet,
        locationPostalCode: req.body.locationPostalCode,
        deliveryType: req.body.deliveryType,
        sellerUsername: req.body.sellerUsername,
        sellerName: req.body.sellerName,
        sellerEmail: req.body.sellerEmail,
        sellerAddress: req.body.sellerAddress 
    }

    postingDb.push(newPosting); // store the new posting into DB
    res.sendStatus(201);
    
})

app.get('/postings', (req, res) => {
    res.json(postingDb);
})


app.get('/postings/:id', (req, res) => {
    const posting = postingDb.find(p => p.id == req.params.id);
    if(posting === undefined) {
        res.sendStatus(404);
    } else {
        res.json(posting);  
    }
})


app.get('/postings/category/:category', (req, res) => {
    const posting = postingDb.filter(p => p.category == req.params.category);
    if(posting === undefined) {
        res.sendStatus(404);
    } else {
        res.json(posting);  
    }
})


app.get('/postings/location/:locationCity', (req, res) => {
    const posting = postingDb.filter(p => p.locationCity === req.params.locationCity);
    if(posting === undefined) {
        res.sendStatus(404);
    } else {
        res.json(posting);  
    }
})

app.get('/postings/date/:dateOfPosting', (req, res) => {
    const posting = postingDb.filter(p => p.dateOfPosting == req.params.dateOfPosting);
    if(posting === undefined) {
        res.sendStatus(404);
    } else {
        res.json(posting);  
    }
})

app.delete('/postings/:id', passport.authenticate('jwt', {session: false}), (req, res) => {
    console.log("req params", req.params.id)
    const posting = postingDb.find(p => p.id == req.params.id);

    if(posting === undefined) {
        res.sendStatus(404);
    } else {       
        if ( req.user.username == posting.sellerUsername){
            postingDb = postingDb.filter(({ id }) => id !== req.params.id);
            res.sendStatus(200);
        } else {
            res.sendStatus(401);
        }
    }
})

app.put('/postings/:id', passport.authenticate('jwt', {session: false}), (req, res) => {
    const posting = postingDb.find(p => p.id == req.params.id);
    if(posting === undefined) {
        res.sendStatus(404);
    } else {
        if ( req.user.username == posting.sellerUsername){
            posting.title = req.body.title,
            posting.description = req.body.description,
            posting.category = req.body.category,
            posting.askingPrice = req.body.askingPrice,
            posting.locationCountry = req.body.locationCountry,
            posting.locationCity = req.body.locationCity,
            posting.locationStreet = req.body.locationStreet,
            posting.locationPostalCode = req.body.locationPostalCode,
            posting.deliveryType = req.body.deliveryType,
            posting.sellerName = req.body.sellerName,
            posting.sellerEmail = req.body.sellerEmail,
            posting.address = req.body.address
            res.sendStatus(200);
        } else {
            res.sendStatus(401);
        }    
    }
})


app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
})

const dotenv = require('dotenv').config()
// import libraries
const express = require("express")
const bcrypt = require("bcrypt")
const app = express()
const initializePassport = require("./passport-config") 
const passport = require("passport")
const flash = require("express-flash")
const session = require("express-session")
const methodOverride = require("method-override")
//for intercom
const crypto = require('crypto');


var INTERCOM_SECRET_KEY = process.env.SECRET_KEY_INTERCOM;
var INTERCOM_APP_ID = process.env.APP_ID;


initializePassport(
    passport,
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id)
    )



const users = []


app.use(express.urlencoded({extended: false}))
app.use(flash())
app.use(session({
    secret : process.env.SECRET_KEY,
    resave : false, // don't resave session variable if nothing is changed
    saveUninitialized : false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride("_method"))

// configure the login funcionality

app.post("/login", checkNotAuthenticated, passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true
}))

// configure the register funcionality
app.post("/register", checkNotAuthenticated, async(req, res)=>{
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10 )
        users.push({
            id : Date.now().toString(),
            name : req.body.name,
            email : req.body.email,
            password : hashedPassword
        })
        console.log(users)
        res.redirect("/login")

    } catch (error) {
        console.log(error)
        res.redirect("/register")
    }
})


// Routes 
app.get('/', checkAuthenticated, (req, res) => {
    const secretKey = INTERCOM_SECRET_KEY; // secret key (keep safe!) 
    const userIdentifier = req.user.id.toString(); // user's id
    const hash = crypto.createHmac('sha256', secretKey).update(userIdentifier).digest('hex');

    res.render("index.ejs", {
        name: req.user.name,
        intercomAppId: INTERCOM_APP_ID,
        user: req.user.id,
        intercomUserHash: hash
    })
})

app.get('/login', checkNotAuthenticated, (req, res) => { 
    res.render("login.ejs")
})

app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render("register.ejs")
})
// end routes

app.delete("/logout", (req, res)=>{
    req.logOut(req.user, err => {
        if(err) return next(err)
        res.redirect("/")}
    )}
)
    


function checkAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return next()
    }
    res.redirect("/login")
}
function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return res.redirect("/")
    }
    next()
}
app.listen(3000)
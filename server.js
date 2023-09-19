
const express = require("express")
const bcrypt = require("bcrypt")
const app = express()
const initializePassport = require("./passport-config") 
const passport = require("passport")
const flash = require("express-flash")
const session = require("express-session")


initializePassport(
    passport,
    email => users.find(user => user.email === email)
    )



const users = []


app.use(express.urlencoded({extended: false}))
app.use(flash())
app.use(session({
    secret : process.env.SECRET_KEY,
    resave : false, // resave session variable if nothing is changed
    saveUnitialized : false
}))
app.use(passport.initialize())
app.use(passport.session)


app.post("/register", async(req, res)=>{
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
app.get('/', (req, res) => {
    res.render("index.ejs")
})

app.get('/login', (req, res) => { 
    res.render("login.ejs")
})

app.get('/register', (req, res) => {
    res.render("register.ejs")
})


app.listen(3000)
const LocalStrategy = require("passport-local").Strategy
const bcrypt = require("bcrypt")

function initialize(passport){
    //function to authenticate users
    const authenticateUsers = async (email, password, done) => {
        //get users by email
        const user = getUserByEmail(email)
        if (user == null) {
            return done(null, false, {message: "No user found with that email"})
        }
        try {
            if (await bcrypt.compare(password, user.password)){
                return done(null, user)
            }
        } catch (error) {
          console.log(error)
          return done(error)  
        }
    }
    passport.use(new LocalStrategy({usernameField: 'email'}))
    passport.serializeUser((user, done) => {})
    passport.deserializeUser((id, done) => {})
}

module.exports(initialize)
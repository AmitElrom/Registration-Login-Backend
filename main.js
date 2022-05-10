// libraries
const { hash, compare } = require('bcrypt')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const express = require('express')
const app = express()

// project files
const { User } = require('./models/userModel')
const { createToken, authenticateToken : auth } = require('./middlewares/jwt')

require('./configs/db')

app.use(express.json())
app.use(cors())
app.use(cookieParser())

// registration
app.post('/signup', async (req,res) => {

    const { body : { email, password } } = req;

    // check if user with same email already exists
    const user = await User.findOne({email})

    if(user) return res.status(400).json({ message : 'User already exists' })

        // hash password
        const hashedPassword = await hash(password, 10)

        // create new user
        try {
            const newUser = await User.create({
                email,
                password : hashedPassword
            })
            
            return res.status(201)
                .json({ message : `new user with email ${newUser.email} was created successfully` })
        } catch (err) {
            return res.status(400).json({ error : err })
        }
})

// login
app.post('/login', async (req,res) => {
    
    const { body : { email, password } } = req;

    // find user in db by email/username/etc
    const user = await User.findOne({email})

    if(!user) res.status(400).json({ error : 'User does not exist' })

    const { password : dbPassword } = user; // hashed password in db
    
    // compare inserted password and password in db(hashed password)
    const match = await compare(password, dbPassword) // match is a boolean value

    if(!match) res.status(400).json({ error : 'Wrong email and password combination' })

    // create token for user
    const accessToken = createToken(user)

    // send access token to cookies
    res.cookie('access-token', accessToken, {
        maxAge : 2.62974383 * 10**9,
        // maxAge is the time until the token expires, 
        // time is milliseconds (1/1000 second), 
        // inserted time equals to 1 month
        httpOnly : true 
        // httpOnly - better scurity
    }).json({ message : 'User logged in' })
})

// example get request
app.get('/profile', auth, (req,res) => {
    res.json(req.body)
})

app.listen(8000, () => {
    console.log('server is on');
})

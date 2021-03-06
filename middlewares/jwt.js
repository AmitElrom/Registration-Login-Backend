require('dotenv').config()

const { sign, verify } = require('jsonwebtoken')

const createToken = (user) => {
    const accessToken = sign({ email : user.email, id : user._id }, 
        process.env.ACCESS_TOKEN_KEY)

    return accessToken
}

// middleware
const authenticateToken = (req,res,next) => {
    const accessToken = req.cookies['access-token']

    if(!accessToken) return res.status(401).json({ error : 'User is not authenticated' })

        // if token exists - check if token in cookies is the same as in env file (ACCESS_TOKEN_KEY)
        try {
            const authenticatedToken = verify(accessToken,process.env.ACCESS_TOKEN_KEY)
            if(authenticatedToken) {
                req.authenticated = true
                req.user = authenticatedToken
                return next() 
                // next - function that makes the next function. only if next exist the request will be performed.
            }
        } catch (err) {
            return res.status(401).json({ error : 'User is not authorized' })
        }
}

module.exports = { createToken, authenticateToken }
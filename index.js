// TOOD

// - SEPARATE ROUTERS FOR
//   - SIGNUP
//   - LOGIN
//   - NOTES

// - ADD TAGS
// - PROTECT NOTES ROUTER
// - FRONT-END

// ===============
// = # IMPORTS # =
// ===============

// ## NODE.JS

// ## ENVIRONMENT
const dotenv = require('dotenv')

// ## DATABASE
const Database = require('better-sqlite3')

// ## EXPRESS
const express = require('express')

// ## AUTH
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

// ## MIDDLEWARE
const cors = require('cors')
const morgan = require('morgan')

// ## VALIDATION
const yup = require('yup')

// ## UUID
const {nanoid} = require('nanoid')

// ==================================
// # INJECT ENVIRONMENTAL VARIABLES #
// ==================================

dotenv.config()

// ================
// # LOGGER SETUP #
// ================

const log = {
    info: (...params) => process.env.NODE_ENV !== 'PRODUCTION' && console.info(...params),
    error: (...params) => process.env.NODE_ENV !== 'PRODUCTION' && console.error(...params)
}

// ====================
// # VALIDATION SETUP #
// ====================

const SIGN_UP_REQUEST_BODY_VALIDATION = yup.object({
    username: yup.string().trim().min(3).matches(/^[a-zA-Z0-9-_.]+$/).required(),
    password: yup.string().trim().min(8).required()
})

const LOGIN_REQUEST_BODY_VALIDATION = SIGN_UP_REQUEST_BODY_VALIDATION

const POST_NOTE_REQUEST_BODY_VALIDATION = yup.object({body: yup.string().trim().required()})
const PUT_NOTE_REQUEST_BODY_VALIDATION = POST_NOTE_REQUEST_BODY_VALIDATION

// ==============
// # AUTH SETUP #
// ==============

const authorizedUserRoute = async (request, response, next) => {

    console.log(request.body, request.headers)
    const authorization = request.get('authorization')
    console.log('AUTHORIZATION', authorization)

    if(!authorization){ return response.status(401).json({'error': 'ERROR :: AUTHORIZATION :: TOKEN MISSING OR MALFORMED'}) }

    const token = authorization.startsWith('bearer ') ? authorization.substring(7) : null

    if (!token) { return response.status(401).json({'error': 'ERROR :: AUTHORIZATION :: TOKEN MISSING OR MALFORMED'}) }

    let token$decoded

    try {
        token$decoded = await jwt.verify(token, process.env.JWT_SECRET)
    } catch (error) {
        return response.status(401).json({'error': 'ERROR :: AUTHORIZATION :: TOKEN INVALID OR EXPIRED'})
    }

    request.user = { username: token$decoded.username }

    next()

}


// ==================
// # DATABASE SETUP #
// ==================

let databasePath

switch (process.env.NODE_ENV) {
    case 'PRODUCTION':
        databasePath = process.env.PRODUCTION_DATABASE_PATH;
        break;
    case 'DEVELOPMENT':
        databasePath = process.env.PRODUCTION_DATABASE_PATH;
        break;
    case 'TEST':
        databasePath = process.env.PRODUCTION_DATABASE_PATH;
        break;
}

const db = new Database(databasePath, {fileMustExist: true})

const SQL_INSERT_USER = db.prepare('INSERT INTO user (username, hashedPassword) VALUES (@username, @hashedPassword)')
const SQL_SELECT_USER = db.prepare('SELECT * FROM user WHERE username = @username')

const SQL_SELECT_ALL_NOTES = db.prepare('SELECT * FROM note WHERE user_username = @user_username')
const SQL_INSERT_NOTE = db.prepare('INSERT INTO note (id, user_username, body) VALUES (@id, @user_username, @body)')
const SQL_SELECT_NOTE = db.prepare('SELECT * FROM note WHERE id = @id')
const SQL_DELETE_NOTE = db.prepare(`DELETE FROM note WHERE id = @id`)
const SQL_UPDATE_NOTE = db.prepare(`UPDATE note SET body = @body WHERE id = @id`)

// ==================
// # BUSINESS LOGIC #
// ==================

// ## AUTH ##

const saltRounds = 10
const addUser = async ({username, password}) => {
    const hashedPassword = await bcrypt.hash(password, saltRounds)
    SQL_INSERT_USER.run({username, hashedPassword})
    return {username}
}

const getUser = (username) => {
    return SQL_SELECT_USER.get({username})
}

const checkUserExists = (username) => {
    return SQL_SELECT_USER.get({username})
}

// ## NOTES ##

const getAllNotes = (user) => {
    return SQL_SELECT_ALL_NOTES.all({user_username: user.username})
}

const getNote = (user, id) => {
    return SQL_SELECT_NOTE.get({user_username: user.username, id})
}

const addNote = (user, body) => {
    const note = {id: nanoid(), user_username: user.username, body}
    SQL_INSERT_NOTE.run(note)
    return note
}

const deleteNote = (user, id) => {
    SQL_DELETE_NOTE.run({username: user.username, id})
}

const updateNote = (username, note) => {
    SQL_UPDATE_NOTE.run(note)
}

// ORDERS
// PRODUCT
// CUSTOMER
// SELLER
// TEA

// ORDER PRODUCT LINES


// ===================
// = # EXPRESS APP # =
// ===================

const app = express()

// =======================
// # PRE-ROUTES MIDDLEWARE
// =======================

// ## MIDDLEWARE - CORS
app.use(cors())

// ## MIDDLEWARE - JSON PARSER
app.use(express.json())

// ## MIDDLEWARE - LOGGER
app.use(morgan('tiny'))

// ## MIDDLEWARE - STATIC FILES
// app.use(express.static('build')) // serve a React app

// ## MIDDLEWARE - EXTRACT TOKEN

// ## AUTH

// ===============
// # ROUTES - INFO
// ===============

app.get('/info', (request, response) => {
})

// ===============
// # ROUTES - AUTH
// ===============

app.post('/auth/sign-up', async (request, response, next) => {
    const {username, password} = request.body
    if (checkUserExists(username)) return response.status(404).json({error: 'ERROR :: SIGN UP :: USERNAME ALREADY EXISTS'})
    const newUser = await addUser({username, password})
    response.status(201).json({user: newUser})
})

app.post('/auth/login', async (request, response, next) => {

    const {username, password} = request.body

    if (!checkUserExists(username)) return response.status(404).json({error: 'ERROR :: LOG IN :: USERNAME OR PASSWORD IS INCORRECT'})

    const user = getUser(username)

    if (!await bcrypt.compare(password, user.hashedPassword)) return response.status(404).json({error: 'ERROR :: LOG IN :: USERNAME OR PASSWORD IS INCORRECT'})

    const token = jwt.sign({username}, process.env.JWT_SECRET, {expiresIn: 60 * 60})

    response.json({username, token})

})


// ====================
// # ROUTES - PAYMENT #
// ====================

// ==================
// # ROUTES - NOTES #
// ==================

app.get('/notes', authorizedUserRoute, (request, response, next) => {
    const notes = getAllNotes(request.user)
    return response.json({notes})
})

app.get('/notes/:id', authorizedUserRoute, (request, response, next) => {
    const note = getNote(request.user, request.params.id)
    note ? response.json(note) : response.status(404).end()
})

app.post('/notes', authorizedUserRoute, (request, response, next) => {

    console.log('body', request.body)
    try {
        POST_NOTE_REQUEST_BODY_VALIDATION.validateSync(request.body)
    } catch (error) {
        return response.status(404).json({error})
    }

    const { body } = request.body
    const user = request.user
    const note = addNote(request.user, body)

    response.status(201).json(note)
})

app.delete('/notes/:id', authorizedUserRoute, (request, response, next) => {
    console.log(deleteNote)
    deleteNote(request.user, request.params.id)
    response.status(204).end()
})

app.put('/notes/:id', authorizedUserRoute, (request, response, next) => {
    const updatedNote = updateNote({id: request.params.id, ...request.body})
    updatedNote ? response.json(updatedNote) : response.status(404).end()
})

// ========================
// # POST-ROUTES MIDDLEWARE
// ========================

// ## UNKNOWN ENDPOINT
app.use((request, response) => {
    response.status(404).send({error: `ERROR :: UNKNOWN ENDPOINT :: ${request.path}`})
})

// ## ERROR HANDLER
app.use((error, request, response, next) => {
    log.error(error)
    next(error)
})

const PORT = process.env.PORT || 4000

app.listen(PORT, () => {
    log.info(`Server is running on PORT :: ${PORT}`)
})


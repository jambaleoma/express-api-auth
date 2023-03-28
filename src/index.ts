import express from 'express';
import dotenv from 'dotenv';
dotenv.config();
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');
const app = express();
const cors = require('cors');
var bodyParser = require('body-parser');
const axios = require('axios');
const bcrypt = require('bcrypt');
const auth = require("../middleware/auth");
const TOKEN_SECRET = process.env.TOKEN_SECRET;
const PORT = process.env.PORT;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use('/api', jsonServer.router('db.json'));
app.use(cors())

// GET ALL USERS
app.get('/users', (req, res) => {
    axios.get('http://localhost:3000/users')
        .then((resp: (any)) => {
            const users = resp.data;
            res.status(200).json(users)
        });
});

// GET ONE USER
app.get('/users/:id', (req, res) => {
    const id = +req.params.id;
    axios.get('http://localhost:3000/users')
        .then((resp: (any)) => {
            const users = resp.data;
            const user = users.filter((u: any) => u.id === id);
            res.status(200).json(user)
        });
});

// CHECK AUTH
app.post('/welcome', auth, (req, res) => {
    res.status(200).send('BENVENUTO 🙌🏻 ');
});

// LOGIN
app.post('/login', (req, res) => {
    if (req.body.email) {
        axios.get('http://localhost:3000/users')
            .then(async (resp: { data: any[]; }) => {
                await resp.data.forEach(async user => {
                    if (await user.email === req.body.email) {
                        if (await bcrypt.compare(req.body.password, user.password)) {
                            const token = await generateAccessToken({
                                email: req.body.email
                            });
                            user.token = token;
                            user.exp = 7200;
                            res.status(200).json(user);
                        } else {
                            res.status(403).send('PASSWORD NON CORRETTA!');
                        }
                    }
                });
            })
            .catch((error: any) => {
                console.log(error);
            });
    } else {
        res.status(400).send('INSERIRE UNA EMAIL!');
    }
})

// CREATE USER
app.post('/users', async (req, res) => {
    // Our register logic starts here
    try {
        // Get user input
        const {
            firstName,
            lastName,
            email,
            password
        } = req.body;

        // Validate user input
        if (!(email && password && firstName && lastName)) {
            res.status(400).send("All input is required");
        }

        // check if user already exist
        // Validate if user exist in our database
        axios.get('http://localhost:3000/users')
            .then(async (responseUsers: { data: any; status: (arg0: number) => { (): any; new(): any; send: { (arg0: string): any; new(): any; }; json: { (arg0: any): void; new(): any; }; }; }) => {
                let data = responseUsers.data;
                let checkFinish = false;
                let userAlreadyExist = false;
                await data.forEach((user: { email: any; }) => {
                    if (user.email === req.body.email) {
                        userAlreadyExist = true;
                        res.status(409).send("User Already Exist. Please Login");
                    }
                });
                checkFinish = true;
                if (!userAlreadyExist && checkFinish) {
                    //Encrypt user password
                    let encryptedPassword = await bcrypt.hash(password, 10);

                    // Create user in our database
                    await axios.post('http://localhost:3000/users', {
                        firstName,
                        lastName,
                        email: email.toLowerCase(), // sanitize: convert email to lowercase
                        password: encryptedPassword,
                    })
                        .then((u: any) => {
                            // Create token
                            const token = generateAccessToken({
                                email: req.body.email
                            });
                            // save user token
                            u.data.token = token;
                            u.data.exp = 7200;

                            // return new user
                            res.status(201).json(u.data);
                        })
                        .catch((err: any) => console.log(err));
                }
            })
    } catch (err) {
        console.log(err);
    }
});

// UPDATE USER
app.put('/users/:id', async (req, res) => {
    try {
        // Get user input
        const { firstName, lastName, email, password } = req.body;
        // UPDATE user in our database
        await axios.put('http://localhost:3000/users/' + req.params.id, {
            firstName,
            lastName,
            email,
            password
        })
            .then((u: any) => {
                // return updated user
                res.status(200).json(u.data);
            })
            .catch((err: any) => console.log(err));
    } catch (err) {
        console.log(err);
    }
});

// MODIFY USER
app.patch('/users/:id', async (req, res) => {
    try {
        // Get user input
        const { firstName, lastName, email, password } = req.body;
        // UPDATE user in our database
        await axios.patch('http://localhost:3000/users/' + req.params.id, {
            firstName,
            lastName,
            email,
            password
        })
            .then((u: any) => {
                // return updated user
                res.status(200).json(u.data);
            })
            .catch((err: any) => console.log(err));
    } catch (err) {
        console.log(err);
    }
});

// DELETE USER
app.delete('/users/:id', (req, res) => {
    const id = +req.params.id;
    axios.delete('http://localhost:3000/users/' + id)
        .then((resp: any) => {
            if (resp.status === 200) {
                res.status(200).send('UTENTE ELIMINATO!');
            } else {
                res.status(404).send('UTENTE NON ELIMINATO!');
            }
        });
});

function generateAccessToken(email: { email: any; }) {
    return jwt.sign(
        email,
        TOKEN_SECRET, {
        expiresIn: '2h'
    }
    );
}

app.listen(PORT, () => {
    console.log(`Example app listening on port ${PORT}`)
})
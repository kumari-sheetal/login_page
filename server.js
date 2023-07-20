

import express from 'express';
import mysql from 'mysql';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
// import cookieParser from 'cookie-parser';

const app = express();
app.use(express.json());
app.use(cors());
// app.use(cookieParser());

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: 'signup'
});
app.post('/register', (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;


    if (!name || !email || !password) {
        return res.status(400).json({ Error: 'Please provide all the required fields: name, email, and password.' });
    }

    // check email already exists in the db
    const EmailQuery = "SELECT * FROM users WHERE email = ?";
    db.query(EmailQuery, [email], (err, result) => {
        if (err) {
            console.error("Error occurred while checking email:", err);
            return res.status(500).json({ Error: 'An error occurred while registering.' });
        }

        if (result.length > 0) {
            // Email already exists
            return res.status(409).json({ Error: 'Email already exists. Please use a different email address.' });
        }

        // Email is unique
       
        bcrypt.genSalt(10, (err, salt) => {
            if (err) return res.json({ Error: "Error generating salt for hashing password" });

            bcrypt.hash(password, salt, (err, hash) => {
                if (err) return res.json({ Error: "Error for hashing Password" });

                const sql = "INSERT INTO users (`name`, `email`, `password`) VALUES (?, ?, ?)";
                const values = [
                    name,
                    email,
                    hash
                ];

                db.query(sql, values, (err, result) => {
                    if (err) {
                        console.error("Error occurred while registering:", err);
                        return res.status(500).json({ Error: 'An error occurred while registering.' });
                    }
                    return res.status(201).json({ message: 'Registration successful!' });
                });
            });
        });
    });
});


app.post('/login', (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    // Check the fields
    if (!email || !password) {
        return res.status(400).json({ Error: 'Please provide both email and password.' });
    }

    // Check  the email exists in the db
    const checkEmailQuery = "SELECT * FROM users WHERE email = ?";
    db.query(checkEmailQuery, [email], (err, result) => {
        if (err) {
            console.error("Error occurred while checking email:", err);
            return res.status(500).json({ Error: 'An error occurred while logging in.' });
        }

        if (result.length === 0) {
            // Email does not exist
            return res.status(401).json({ Error: 'Invalid email or password.' });
        }

        // Email exists, verify the password
        const hashedPassword = result[0].password;
        bcrypt.compare(password, hashedPassword, (err, isMatch) => {
            if (err) {
                console.error("Error occurred while comparing passwords:", err);
                return res.status(500).json({ Error: 'An error occurred while logging in.' });
            }

            if (!isMatch) {
                // Password does not match
                return res.status(401).json({ Error: 'Invalid email or password.' });
            }

            // Password matches, issue a JWT
            const user = { id: result[0].id, name: result[0].name, email: result[0].email };
            const secretKey = "aadassadhadgjag"; 
            const token = jwt.sign(user, secretKey, { expiresIn: '1h' });

            // Set the JWT as a cookie
            res.cookie('token', token, { httpOnly: true, maxAge: 3600000 }); // 1 hour 

         
            return res.status(200).json({ message: 'Login successful!', token: token });
        });
    });
});


app.listen(3000, () => {
    console.log("Running......");
});




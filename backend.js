// Import necessary modules
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const { MongoClient } = require('mongodb');

// Initialize Express app
const app = express();

// Middleware
app.use(bodyParser.json());

// MongoDB Connection
const uri = 'mongodb://localhost:27017';
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });
let db;

async function connectToDB() {
    try {
        await client.connect();
        db = client.db('influencersDB');
        console.log('Connected to MongoDB');
    } catch (error) {
        console.error('Error connecting to MongoDB:', error);
    }
}

connectToDB();

// User Model
const User = db.collection('users');

// Influencer Model
const Influencer = db.collection('influencers');

// Routes

// User Registration
app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        // Create user
        const newUser = {
            _id: uuidv4(),
            email,
            password: hashedPassword
        };
        // Insert user into database
        await User.insertOne(newUser);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        // Check password
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, 'secret_key', { expiresIn: '1h' });
        res.status(200).json({ token });
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        req.user = user;
        next();
    });
}

// Example API to get all influencers (protected route)
app.get('/influencers', authenticateToken, async (req, res) => {
    try {
        const influencers = await Influencer.find().toArray();
        res.status(200).json(influencers);
    } catch (error) {
        console.error('Error getting influencers:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Example API to send email to influencers
app.post('/email', authenticateToken, async (req, res) => {
    try {
        const { subject, message } = req.body;
        // Fetch list of influencers from database
        const influencers = await Influencer.find().toArray();
        // Send email to each influencer
        for (const influencer of influencers) {
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: 'your_email@gmail.com',
                    pass: 'your_password'
                }
            });
            const mailOptions = {
                from: 'your_email@gmail.com',
                to: influencer.email,
                subject,
                text: message
            };
            await transporter.sendMail(mailOptions);
        }
        res.status(200).json({ message: 'Email sent to influencers' });
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

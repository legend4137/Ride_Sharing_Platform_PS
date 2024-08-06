require("dotenv").config();

const express = require('express');
const app = express();
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('./User');
const authorize = require('./authorize');

const port = 5000;

const uri = process.env.MONGOOSE_URI;

mongoose
  .connect(uri)
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.error("Failed to connect to MongoDB Atlas:", err));

// Middleware to parse JSON bodies
app.use(express.json());

// Enable CORS
app.use(cors());

app.get('/', (req, res) => {
    res.send('Hello from the backend!');
});

// Register
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword, role });
    await user.save();
    res.status(201).send('User registered');
});
  
// Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send('Invalid credentials');
    }
    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET);
    res.json({ token });
});

app.get('/admin', authorize(['admin']), async (req, res) => {
    const user =await User.findById(req.user.userId).select('username');

    if (user) {
        res.json({ username: user.username });
    } else {
        res.status(404).json({ error: 'User not found' });
    }
    // res.send('Welcome Admin');
});

app.get('/user', authorize(['traveler', 'admin']), async (req, res) => {
    const user =await User.findById(req.user.userId).select('username');

    if (user) {
        res.json({ username: user.username });
    } else {
        res.status(404).json({ error: 'User not found' });
    }
});

app.get('/api/data', (req, res) => {
    res.json({ message: 'Hello from the API' });
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

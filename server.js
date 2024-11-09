require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcrypt');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB URI and Client Setup
const mongoUri = process.env.MONGODB_URI;
const client = new MongoClient(mongoUri);
let usersCollection;

// Connect to MongoDB
async function connectToDatabase() {
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        const database = client.db('userDB_reset_password');
        usersCollection = database.collection('userDB_reset_password');
    } catch (err) {
        console.error('Failed to connect to MongoDB', err);
        process.exit(1);
    }
}
connectToDatabase();

// Mongoose connection for User Schema
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('Connected to MongoDB using Mongoose'))
    .catch(error => console.error('MongoDB connection error:', error));

// Define User Schema and Model
const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    resetKey: String,
    resetExpires: Date,
    password: String,
    invalidLoginAttempts: { type: Number, default: 0 },
    accountLockedUntil: Date,
    lastLoginTime: Date,
    studentIDNumber: String,
    role: String,
});

const User = mongoose.model('User', userSchema, 'userDB_reset_password');

// Configure SendGrid API Key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(helmet()); // Set security-related HTTP headers

// Session management with MongoDB
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoUri }),
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 60 * 1000, // Session expires after 30 minutes
    }
}));

// Rate limiting middleware
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
});
app.use(limiter);

const loginLimiter = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // Limit each IP to 5 requests per window
    message: 'Too many login attempts, please try again after 30 minutes.',
    handler: (req, res, next, options) => {
        res.status(options.statusCode).json({ success: false, message: options.message });
    }
});

// Utility Functions
const generateCode = () => Math.random().toString(36).slice(-8);

async function sendResetCodeEmail(email, resetCode) {
    const msg = {
        to: email,
        from: 'smalipe9@gmail.com',
        subject: 'Password Reset Request',
        text: `Your password reset code is: ${resetCode}`,
        html: `<p>Your password reset code is:</p><h3>${resetCode}</h3>`,
    };

    return sgMail.send(msg);
}

function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hashSync(password, saltRounds);
}

function isValidPassword(password) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+={}\[\]:;"'<>,.?/~`-]).{8,}$/;
    return passwordRegex.test(password);
}

// Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized access. Please log in.' });
    }
}

// Routes
app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

app.post('/send-password-reset', async (req, res) => {
    const { email } = req.body;

    if (!validator.isEmail(email)) {
        return res.status(400).json({ success: false, message: 'Invalid email format.' });
    }

    try {
        let user = await User.findOne({ email });
        const resetCode = generateCode();

        if (user) {
            user.resetKey = resetCode;
            user.resetExpires = new Date(Date.now() + 3600000); // 1 hour expiry
            await user.save();
        } else {
            user = new User({ email, resetKey: resetCode, resetExpires: new Date(Date.now() + 3600000) });
            await user.save();
        }

        await sendResetCodeEmail(email, resetCode);
        res.json({ success: true, redirectUrl: '/reset-password.html' });
    } catch (error) {
        console.error('Error processing your request:', error);
        res.status(500).json({ success: false, message: 'Error processing your request', error: error.message });
    }
});

app.post('/reset-password', async (req, res) => {
    const { resetKey, newPassword } = req.body;

    try {
        const user = await User.findOne({ resetKey, resetExpires: { $gt: new Date() } });

        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid or expired reset key.' });
        }

        const hashedPassword = hashPassword(newPassword);
        await User.updateOne({ _id: user._id }, {
            $set: { password: hashedPassword, resetKey: null, resetExpires: null }
        });

        res.json({ success: true, message: 'Your password has been successfully reset.', redirectUrl: '/index.html' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ success: false, message: 'Error resetting password' });
    }
});

app.post('/signup', async (req, res) => {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
        return res.status(400).json({ success: false, message: 'Full name, email, and password are required.' });
    }

    if (!validator.isEmail(email)) {
        return res.status(400).json({ success: false, message: 'Invalid email format.' });
    }

    if (!isValidPassword(password)) {
        return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, and one number.' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email is already used.' });
        }

        const hashedPassword = hashPassword(password);
        const newUser = new User({ fullName, email, password: hashedPassword, createdAt: new Date() });
        await newUser.save();

        res.json({ success: true, message: 'Account created successfully!' });
    } catch (error) {
        console.error('Error creating account:', error.stack || error);
        res.status(500).json({ success: false, message: 'An internal server error occurred.', error: error.message });
    }
});

app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/user-details', isAuthenticated, async (req, res) => {
    try {
        const email = req.session.email;
        if (!email) {
            return res.status(401).json({ success: false, message: 'Unauthorized access.' });
        }

        const user = await usersCollection.findOne({ email }, { projection: { email: 1 } });
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        res.json({ success: true, user: { email: user.email } });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ success: false, message: 'Error fetching user details.' });
    }
});

app.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ success: false, message: 'Invalid email or password.' });
        }

        req.session.userId = user._id;
        req.session.email = user.email;
        req.session.lastLoginTime = new Date();

        user.invalidLoginAttempts = 0;
        await user.save();

        res.json({ success: true, message: 'Login successful.', redirectUrl: '/dashboard' });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});
app.post('/logout', (req, res) => {
    if (req.session) {
        // Destroy session
        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).json({ success: false, message: 'Error logging out.' });
            }
            // Redirect to login or home page after logout
            res.json({ success: true, message: 'Successfully logged out.', redirectUrl: '/login' });
        });
    } else {
        res.status(400).json({ success: false, message: 'No active session found.' });
    }
});


app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`You can visit the login page at: http://localhost:${PORT}`);
});
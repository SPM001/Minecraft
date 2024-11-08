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
const mongoUri = process.env.MONGODB_URI; // Use your actual MongoDB URI
const client = new MongoClient(mongoUri);
let usersCollection;

// Connect to MongoDB
async function connectToDatabase() {
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        const database = client.db('userDB_reset_password'); // Replace with your database name
        usersCollection = database.collection('userDB_reset_password'); // Use your actual collection name
    } catch (err) {
        console.error('Failed to connect to MongoDB', err);
        process.exit(1);
    }
}
connectToDatabase();

// Mongoose connection for User Schema
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('Connected to MongoDB using Mongoose');
    })
    .catch((error) => {
        console.error('MongoDB connection error:', error);
    });

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
app.use(cors()); // Enable CORS for all routes
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(helmet()); // Set security-related HTTP headers

// Session management with MongoDB
// Session management with MongoDB store
app.use(session({
    secret: process.env.SESSION_SECRET, // Ensure you have a SESSION_SECRET in your .env file
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoUri }), // Use your MongoDB URI
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Set to true if you're using HTTPS
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 60 * 1000 // Session expires after 30 minutes
    }
}));

// Rate limiting to prevent abuse
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // Limit each IP to 100 requests per window
});
app.use(limiter);

// Login Rate Limiter
const loginLimiter = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: 'Too many login attempts, please try again after 30 minutes.',
    handler: function (req, res, next, options) {
        res.status(options.statusCode).json({ success: false, message: options.message });
    }
});

// Generate Random Reset Code Function
function generateCode() {
    return Math.random().toString(36).slice(-8); // Generate an 8-character code
}

// Send Reset Code Email Function
async function sendResetCodeEmail(email, resetCode) {
    const msg = {
        to: email,
        from: 'smalipe9@gmail.com', // Replace with your verified SendGrid email
        subject: 'Password Reset Request',
        text: `Your password reset code is: ${resetCode}`,
        html: `<p>Your password reset code is:</p><h3>${resetCode}</h3>`,
    };

    return sgMail.send(msg);
}

// Password Hashing Function
function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hashSync(password, saltRounds);
}

// Password Validation Function
/// Password Validation Function
function isValidPassword(password) {
    // Requires at least one uppercase letter, one lowercase letter, one number,
    // and at least 8 characters including special characters.
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+={}\[\]:;"'<>,.?/~`-]).{8,}$/;
    return passwordRegex.test(password);
}



// Serve Forgot Password HTML Form
app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

// Forgot Password Endpoint
app.post('/send-password-reset', async (req, res) => {
    const { email } = req.body;

    // Validate email
    if (!validator.isEmail(email)) {
        return res.status(400).json({ success: false, message: 'Invalid email format.' });
    }

    try {
        let user = await User.findOne({ email: email });
        const resetCode = generateCode();

        if (user) {
            user.resetKey = resetCode;
            user.resetExpires = new Date(Date.now() + 3600000); // 1 hour expiry
            await user.save();
        } else {
            user = new User({
                email: email,
                resetKey: resetCode,
                resetExpires: new Date(Date.now() + 3600000) // 1 hour expiry
            });
            await user.save();
        }

        // Send email with the new token
        await sendResetCodeEmail(email, resetCode);
        res.json({ success: true, redirectUrl: '/reset-password.html' });
    } catch (error) {
        console.error('Error processing your request:', error);
        res.status(500).json({ success: false, message: 'Error processing your request', error: error.message });
    }
});

// Reset Password Endpoint
app.post('/reset-password', async (req, res) => {
    const { resetKey, newPassword } = req.body;

    try {
        const user = await User.findOne({
            resetKey: resetKey,
            resetExpires: { $gt: new Date() }
        });

        if (!user) {
            res.status(400).json({ success: false, message: 'Invalid or expired reset key.' });
            return;
        }

        const hashedPassword = hashPassword(newPassword);
        await User.updateOne(
            { _id: user._id },
            {
                $set: {
                    password: hashedPassword,
                    resetKey: null,
                    resetExpires: null
                }
            }
        );

        res.json({ success: true, message: 'Your password has been successfully reset.', redirectUrl: '/index.html' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ success: false, message: 'Error resetting password' });
    }
});

// Sign Up Route
// Sign Up Route
app.post('/signup', async (req, res) => {
    const { fullName, email, password } = req.body;

    // Validate input
    if (!fullName || !email || !password) {
        return res.status(400).json({ success: false, message: 'Full name, email, and password are required.' });
    }

    // Validate email format
    if (!validator.isEmail(email)) {
        return res.status(400).json({ success: false, message: 'Invalid email format.' });
    }

    // Validate password strength
    if (!isValidPassword(password)) {
        return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, and one number.' });
    }

    try {
        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email is already used.' }); // Updated message here
        }

        const hashedPassword = hashPassword(password);
        const newUser = new User({
            fullName: fullName,
            email: email,
            password: hashedPassword,
            createdAt: new Date()
        });

        await newUser.save();
        res.json({ success: true, message: 'Account created successfully!' });
    } catch (error) {
        console.error('Error creating account:', error.stack || error);
        res.status(500).json({ success: false, message: 'An internal server error occurred.', error: error.message });
    }
});

// Authentication Middleware
// Place this at the top, after the required imports
// Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next(); // User is authenticated, proceed to the next middleware or route
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized access. Please log in.' });
    }
}

// Your other route definitions here...

// Protect the dashboard route
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html')); // Serve your dashboard page
});



// Fetch user details route
app.get('/user-details', isAuthenticated, async (req, res) => {
    try {
        const email = req.session.email; // Ensure we're using session.email
        if (!email) {
            return res.status(401).json({ success: false, message: 'Unauthorized access.' });
        }
        // Fetch user details from the database
        const user = await usersCollection.findOne(
            { email: email }, // Use the correct field name here
            { projection: { email: 1 } } // Change emaildb to email
        );
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        // Return only necessary details
        res.json({
            success: true,
            user: {
                email: user.email // Make sure to return the correct field here
            }
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ success: false, message: 'Error fetching user details.' });
    }
});




// Login Endpoint (Revised)
app.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    // Input validation
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }
    if (!validator.isEmail(email)) {
        return res.status(400).json({ success: false, message: 'Invalid email format.' });
    }

    try {
        const user = await User.findOne({ email: email });
        if (!user) {
            return res.status(404).json({ success: false, message: 'Account does not exist.' });
        }

        console.log("Before checking lock status:", user.accountLockedUntil);

        // Check if the account is locked
        if (user.accountLockedUntil) {
            // Check if the lock time has expired
            if (user.accountLockedUntil < new Date()) {
                user.accountLockedUntil = null; // Unlock the account
                user.invalidLoginAttempts = 0; // Reset invalid attempts
                await user.save(); // Save changes to the user record
                console.log("Account unlocked:", user);
            } else {
                return res.status(403).json({ success: false, message: 'Account is locked. Please try again later.' });
            }
        }

        // Proceed with password checking
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            user.invalidLoginAttempts += 1; // Increment invalid attempts
            if (user.invalidLoginAttempts >= 3) {
                user.accountLockedUntil = new Date(Date.now() + 15 * 60 * 1000); // Lock for 15 minutes
            }
            await user.save();
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }

        // Successful login
        req.session.userId = user._id;
        req.session.email = user.email; // Add this line to store the email in the session
        user.lastLoginTime = new Date();
        user.invalidLoginAttempts = 0; // Reset counter on successful login
        user.accountLockedUntil = null; // Unlock the account upon successful login
        await user.save(); // Save changes to the user record

        console.log("After successful login:", user);
        res.json({ success: true, message: 'Login successful!', userId: user._id });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// Logout Endpoint
// Logout Route
app.post('/logout', async (req, res) => {
    if (!req.session.userId) {
        return res.status(400).json({ success: false, message: 'No user is logged in.' });
    }
    try {
        req.session.destroy(err => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).json({ success: false, message: 'Logout failed.' });
            }
            res.clearCookie('connect.sid');
            res.json({ success: true, message: 'Logged out successfully.' });
        });
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).json({ success: false, message: 'Logout failed.' });
    }
});

// Start the Server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

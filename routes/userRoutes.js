const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: process.env.EMAIL_PORT == 465,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Middleware to protect routes that require a user to be logged in
const requireUserLogin = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Route to send OTP for registration
router.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // OTP is valid for 10 minutes

    try {
        // Store OTP and email in the user's session temporarily
        req.session.otp = otp;
        req.session.otpExpires = otpExpires;
        req.session.emailForRegistration = email;

        const mailOptions = {
            from: `"digiROCK Solution" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Your Verification Code',
            html: `<p>Your OTP for registration is: <strong>${otp}</strong>. It is valid for 10 minutes.</p>`,
        };
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'OTP sent successfully.' });
    } catch (err) {
        console.error("Error sending OTP:", err);
        res.status(500).json({ message: 'Server error while sending OTP.' });
    }
});

// Route to handle the final registration form submission
router.post('/register', async (req, res) => {
    const { user_id, password, name, contact_number, email, register_as, address, referral_code, otp } = req.body;

    // Verify the OTP from the session
    if (otp !== req.session.otp || new Date() > new Date(req.session.otpExpires) || email !== req.session.emailForRegistration) {
        return res.status(400).send('Invalid or expired OTP. Please try again.');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (user_id, password, name, contact_number, email, register_as, address, referral_code, is_verified) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)',
            [user_id, hashedPassword, name, contact_number, email, register_as, address, referral_code]
        );

        // Send a welcome email with their credentials
        const mailOptions = {
            from: `"digiROCK Solution" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Registration Successful!',
            html: `<h1>Welcome to digiROCK Solution!</h1>
                   <p>Your account has been created successfully.</p>
                   <p><b>Your User ID:</b> ${user_id}</p>
                   <p><b>Your Password:</b> ${password}</p>
                   <p>You can now log in to your account.</p>`,
        };
        await transporter.sendMail(mailOptions);
        
        // Clear the temporary OTP data from the session
        delete req.session.otp;
        delete req.session.otpExpires;
        delete req.session.emailForRegistration;

        res.redirect('/thank-you');
    } catch (err) {
        console.error("Registration error:", err);
        if (err.code === '23505') { // Handle cases where User ID or Email already exists
            return res.status(400).send('User ID or Email already exists.');
        }
        res.status(500).send('Server error during registration.');
    }
});

// Handle the user login form submission
router.post('/login', async (req, res) => {
    const { user_id_or_email, password } = req.body;
    try {
        // Find a verified user with the matching user_id or email
        const result = await pool.query('SELECT * FROM users WHERE (user_id = $1 OR email = $1) AND is_verified = TRUE', [user_id_or_email]);
        
        if (result.rows.length === 0) {
            return res.render('home/login', { error: 'Invalid credentials or account not verified.' });
        }

        const user = result.rows[0];
        // Compare the submitted password with the hashed password in the database
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            // If passwords match, store user info in the session
            req.session.user = {
                id: user.id,
                userId: user.user_id,
                name: user.name,
                email: user.email,
                register_as: user.register_as
            };
            res.redirect('/user-dashboard');
        } else {
            res.render('home/login', { error: 'Invalid credentials.' });
        }
    } catch (err) {
        console.error("Login error:", err);
        res.render('home/login', { error: 'An error occurred. Please try again.' });
    }
});

// Display the user dashboard page (requires user to be logged in)
router.get('/user-dashboard', requireUserLogin, (req, res) => {
    res.render('user/user-dashboard', { user: req.session.user });
});

// Handle user logout
router.get('/logout-user', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/user-dashboard');
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

module.exports = router;

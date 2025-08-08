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

// Route to send OTP
router.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    try {
        // Store OTP in session temporarily
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

// Route to handle final registration
router.post('/register', async (req, res) => {
    const { user_id, password, name, contact_number, email, register_as, address, referral_code, otp } = req.body;

    // Verify OTP
    if (otp !== req.session.otp || new Date() > new Date(req.session.otpExpires) || email !== req.session.emailForRegistration) {
        return res.status(400).send('Invalid or expired OTP. Please try again.');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (user_id, password, name, contact_number, email, register_as, address, referral_code, is_verified) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)',
            [user_id, hashedPassword, name, contact_number, email, register_as, address, referral_code]
        );

        // Send confirmation email
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
        
        // Clear session data
        delete req.session.otp;
        delete req.session.otpExpires;
        delete req.session.emailForRegistration;

        res.redirect('/thank-you'); // Or a custom "registration-success" page
    } catch (err) {
        console.error("Registration error:", err);
        if (err.code === '23505') { // Unique constraint violation
            return res.status(400).send('User ID or Email already exists.');
        }
        res.status(500).send('Server error during registration.');
    }
});

module.exports = router;

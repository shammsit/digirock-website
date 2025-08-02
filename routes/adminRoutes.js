const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer'); // Import Nodemailer
require('dotenv').config();

// --- NODEMAILER TRANSPORTER SETUP ---
// This uses your custom domain's email credentials
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_PORT == 465, // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});


// --- DATABASE POOL (FIXED FOR DEPLOYMENT) ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const noticeStorage = multer.diskStorage({
  destination: './public/notices/',
  filename: function(req, file, cb){
    cb(null, 'notice-' + Date.now() + path.extname(file.originalname));
  }
});
const uploadNotice = multer({ storage: noticeStorage }).single('attachment');

// --- MIDDLEWARE FOR AUTHENTICATION & AUTHORIZATION ---
const requireAdminLogin = (req, res, next) => {
    if (!req.session.isAdmin) { return res.redirect('/monitor_admin'); }
    // Make role available to all templates rendered after this middleware
    res.locals.adminRole = req.session.adminRole; 
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
};

// Middleware to check for owner role
const requireOwner = (req, res, next) => {
    if (req.session.adminRole !== 'owner') {
        return res.status(403).send('Forbidden: You do not have permission to access this page.');
    }
    next();
};


// --- ADMIN LOGIN/LOGOUT & DASHBOARD ---
router.get('/monitor_admin', (req, res) => { res.render('admin/monitor_admin'); });

router.post('/admin-login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.redirect('/monitor_admin');
    }
    const admin = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, admin.password);
    if (passwordMatch) {
      req.session.isAdmin = true;
      req.session.adminId = admin.id; // Store admin's ID in session
      req.session.adminName = admin.name;
      req.session.adminRole = admin.role; // Store admin's role in session
      res.redirect('/dashboard');
    } else {
      res.redirect('/monitor_admin');
    }
  } catch (err) {
    console.error("CRITICAL ERROR in /admin-login route:", err);
    res.status(500).send('Server error during login.');
  }
});

router.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// --- PASSWORD RESET ROUTES ---
router.get('/forgot-password', (req, res) => {
    res.render('admin/forgot-password', { message: null });
});

router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const { rows } = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
        if (rows.length === 0) {
            return res.render('admin/forgot-password', { message: 'If an account with that email exists, a password reset link has been sent.' });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const expires = new Date(Date.now() + 3600000); // 1 hour

        await pool.query(
            'UPDATE admins SET password_reset_token = $1, password_reset_expires = $2 WHERE email = $3',
            [tokenHash, expires, email]
        );

        const resetLink = `https://www.digirocksolution.co.in/reset-password/${token}`;

        // **SEND THE EMAIL**
        const mailOptions = {
            from: `"digiROCK Admin" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset Request for digiROCK',
            html: `
                <p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
                <p>Please click on the following link, or paste this into your browser to complete the process:</p>
                <a href="${resetLink}">${resetLink}</a>
                <p>This link will expire in one hour.</p>
                <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
            `
        };

        await transporter.sendMail(mailOptions);

        res.render('admin/forgot-password', { message: 'If an account with that email exists, a password reset link has been sent.' });

    } catch (err) {
        console.error("Forgot Password Error:", err);
        res.status(500).send('Server error during password reset process.');
    }
});

router.get('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    try {
        const { rows } = await pool.query(
            'SELECT * FROM admins WHERE password_reset_token = $1 AND password_reset_expires > NOW()',
            [tokenHash]
        );

        if (rows.length === 0) {
            return res.status(400).send('Password reset token is invalid or has expired.');
        }

        res.render('admin/reset-password');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error.');
    }
});

router.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password, passwordConfirm } = req.body;
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    if (password !== passwordConfirm) {
        return res.status(400).send('Passwords do not match.');
    }

    try {
        const { rows } = await pool.query(
            'SELECT * FROM admins WHERE password_reset_token = $1 AND password_reset_expires > NOW()',
            [tokenHash]
        );

        if (rows.length === 0) {
            return res.status(400).send('Password reset token is invalid or has expired.');
        }

        const admin = rows[0];
        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.query(
            'UPDATE admins SET password = $1, password_reset_token = NULL, password_reset_expires = NULL WHERE id = $2',
            [hashedPassword, admin.id]
        );

        res.redirect('/monitor_admin');

    } catch (err) {
        console.error(err);
        res.status(500).send('Server error.');
    }
});


router.get('/dashboard', requireAdminLogin, async (req, res) => { 
  try {
    const [
      donationData,
      ratingData,
      feedbackData,
      mailData,
      noticeData,
      recentDonationsData
    ] = await Promise.all([
      pool.query('SELECT COUNT(*) as count, SUM(amount) as total FROM donations'),
      pool.query('SELECT COUNT(*) as count, AVG(rating) as average FROM ratings'),
      pool.query('SELECT COUNT(*) as count FROM feedbacks'),
      pool.query('SELECT COUNT(*) as count FROM contact_messages'),
      pool.query('SELECT COUNT(*) as count FROM notices WHERE expire_time IS NULL OR expire_time > NOW()'),
      pool.query('SELECT * FROM donations ORDER BY created_at DESC LIMIT 5')
    ]);

    const stats = {
      totalDonations: donationData.rows[0].total || 0,
      donationCount: donationData.rows[0].count,
      averageRating: parseFloat(ratingData.rows[0].average || 0).toFixed(2),
      ratingCount: ratingData.rows[0].count,
      feedbackCount: feedbackData.rows[0].count,
      mailCount: mailData.rows[0].count,
      activeNotices: noticeData.rows[0].count,
    };

    res.render('admin/dashboard', { 
      adminName: req.session.adminName,
      stats: stats,
      recentDonations: recentDonationsData.rows
    });

  } catch (err) {
    console.error("Error fetching dashboard data:", err);
    res.status(500).send("Could not load dashboard data.");
  }
});


// --- NOTICE MANAGEMENT ROUTES ---
router.get('/admin/give-notice', requireAdminLogin, (req, res) => {
  res.render('admin/give-notice');
});

router.post('/admin/give-notice', requireAdminLogin, (req, res) => {
  uploadNotice(req, res, async (err) => {
    if (err) { return res.status(500).send('File upload error'); }
    const { notice_type, title, body_text, release_time, expire_time } = req.body;
    const attachmentPath = req.file ? req.file.path.replace('public', '') : null;
    const expireTimeOrNull = expire_time ? expire_time : null;
    try {
      await pool.query(
        'INSERT INTO notices (notice_type, title, body_text, attachment_path, release_time, expire_time) VALUES ($1, $2, $3, $4, $5, $6)',
        [notice_type, title, body_text, attachmentPath, release_time, expireTimeOrNull]
      );
      res.redirect('/admin/notices');
    } catch (dbErr) {
      console.error(dbErr);
      res.status(500).send('Database error');
    }
  });
});

router.get('/admin/notices', requireAdminLogin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM notices ORDER BY release_time DESC');
    res.render('admin/admin-notices', { notices: rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

router.get('/admin/notices/edit/:id', requireAdminLogin, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query('SELECT * FROM notices WHERE id = $1', [id]);
    if (rows.length > 0) {
      res.render('admin/edit-notice', { notice: rows[0] });
    } else {
      res.redirect('/admin/notices');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

router.post('/admin/notices/update/:id', requireAdminLogin, (req, res) => {
  uploadNotice(req, res, async (err) => {
    const { id } = req.params;
    if (err) { return res.status(500).send('File upload error'); }
    
    const { notice_type, title, body_text, release_time, expire_time, current_attachment } = req.body;
    let attachmentPath = current_attachment;
    if (req.file) {
      attachmentPath = req.file.path.replace('public', '');
    }
    const expireTimeOrNull = expire_time ? expire_time : null;

    try {
      await pool.query(
        `UPDATE notices SET 
          notice_type = $1, title = $2, body_text = $3, attachment_path = $4, release_time = $5, expire_time = $6 
         WHERE id = $7`,
        [notice_type, title, body_text, attachmentPath, release_time, expireTimeOrNull, id]
      );
      res.redirect('/admin/notices');
    } catch (dbErr) {
      console.error(dbErr);
      res.status(500).send('Database error');
    }
  });
});

router.post('/admin/notices/delete/:id', requireAdminLogin, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM notices WHERE id = $1', [id]);
        res.redirect('/admin/notices');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// --- RATINGS ANALYSIS ROUTE ---
router.get('/admin/ratings', requireAdminLogin, async (req, res) => {
    const timeFilter = req.query.time_filter || 'all';
    let whereClause = '';
    
    switch (timeFilter) {
        case 'this_year':
            whereClause = `WHERE date_trunc('year', created_at) = date_trunc('year', CURRENT_TIMESTAMP)`;
            break;
        case 'this_month':
            whereClause = `WHERE date_trunc('month', created_at) = date_trunc('month', CURRENT_TIMESTAMP)`;
            break;
        case 'this_week':
            whereClause = `WHERE date_trunc('week', created_at) = date_trunc('week', CURRENT_TIMESTAMP)`;
            break;
    }

    try {
        const ratingsResult = await pool.query(`SELECT * FROM ratings ${whereClause} ORDER BY created_at DESC`);
        const summaryResult = await pool.query(`SELECT rating, COUNT(*) as count FROM ratings ${whereClause} GROUP BY rating ORDER BY rating DESC`);
        
        const chartData = {
            labels: summaryResult.rows.map(row => `${row.rating} Star`),
            data: summaryResult.rows.map(row => row.count)
        };

        res.render('admin/admin-ratings', {
            ratings: ratingsResult.rows,
            chartData: JSON.stringify(chartData),
            currentTimeFilter: timeFilter
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// --- MAIL MANAGEMENT ROUTES ---
router.get('/admin/mails', requireAdminLogin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM contact_messages ORDER BY created_at DESC');
    res.render('admin/admin-mails', { messages: rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

router.post('/admin/mails/delete/:id', requireAdminLogin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM contact_messages WHERE id = $1', [id]);
    res.redirect('/admin/mails');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// --- FEEDBACK MANAGEMENT ROUTES ---
router.get('/admin/feedbacks', requireAdminLogin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM feedbacks ORDER BY created_at DESC');
    res.render('admin/admin-feedbacks', { feedbacks: rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

router.post('/admin/feedbacks/delete/:id', requireAdminLogin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM feedbacks WHERE id = $1', [id]);
    res.redirect('/admin/feedbacks');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// --- DONATION MANAGEMENT ROUTES ---
router.get('/admin/donations', requireAdminLogin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM donations ORDER BY created_at DESC');
    res.render('admin/admin-donations', { donations: rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

router.post('/admin/donations/delete/:id', requireAdminLogin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM donations WHERE id = $1', [id]);
    res.redirect('/admin/donations');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// --- ADMIN MANAGEMENT ROUTES (PROTECTED) ---
router.get('/admin/manage-admins', requireAdminLogin, requireOwner, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, name, email, role FROM admins ORDER BY name');
    res.render('admin/manage-admins', { 
      admins: rows,
      currentAdminId: req.session.adminId // Pass current admin's ID to the template
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

router.post('/admin/add-admin', requireAdminLogin, requireOwner, async (req, res) => {
  const { name, email, password, role } = req.body; // Add role to destructuring
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    // Add role to the INSERT query
    await pool.query(
      'INSERT INTO admins (name, email, password, role) VALUES ($1, $2, $3, $4)',
      [name, email, hashedPassword, role]
    );
    res.redirect('/admin/manage-admins');
  } catch (err) {
    console.error(err);
    if (err.code === '23505') { 
      return res.status(400).send('An admin with this email already exists.');
    }
    res.status(500).send('Server error');
  }
});

router.post('/admin/delete-admin/:id', requireAdminLogin, requireOwner, async (req, res) => {
  const { id } = req.params;
  try {
    // Prevent the logged-in user from deleting themselves
    if (id == req.session.adminId) {
        return res.status(400).send("You cannot delete your own account.");
    }
    
    const countResult = await pool.query('SELECT COUNT(*) FROM admins');
    if (parseInt(countResult.rows[0].count, 10) > 1) {
      await pool.query('DELETE FROM admins WHERE id = $1', [id]);
    }
    res.redirect('/admin/manage-admins');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

module.exports = router;

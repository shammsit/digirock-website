const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

// --- NODEMAILER TRANSPORTER SETUP ---
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_PORT == 465,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});


// --- DATABASE POOL WITH TIMEZONE FIX ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
// This ensures all database operations use the correct timezone
pool.on('connect', (client) => {
  client.query("SET TIME ZONE 'Asia/Kolkata'");
});


const noticeStorage = multer.diskStorage({
  destination: './public/notices/',
  filename: function(req, file, cb){
    cb(null, 'notice-' + Date.now() + path.extname(file.originalname));
  }
});
const uploadNotice = multer({ storage: noticeStorage }).single('attachment');

// --- MIDDLEWARE ---
const requireAdminLogin = (req, res, next) => {
    if (!req.session.isAdmin) { return res.redirect('/monitor_admin'); }
    res.locals.adminRole = req.session.adminRole; 
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
};

const requireOwner = (req, res, next) => {
    if (req.session.adminRole !== 'owner') {
        return res.status(403).send('Forbidden: You do not have permission to access this page.');
    }
    next();
};

// **UPDATED** Permission Checking Middleware for Manual Requests
const checkPermission = (section) => {
    return async (req, res, next) => {
        const adminId = req.session.adminId;
        const adminRole = req.session.adminRole;

        // Owner has access to everything
        if (adminRole === 'owner') {
            return next();
        }

        try {
            // Check if permission already exists in the permissions table
            const permResult = await pool.query(
                'SELECT * FROM admin_permissions WHERE admin_id = $1 AND allowed_section = $2',
                [adminId, section]
            );

            if (permResult.rows.length > 0) {
                return next(); // Permission granted, continue to the actual page
            }
            
            // If no permission, check if a request is already pending
            const requestResult = await pool.query(
                'SELECT * FROM access_requests WHERE admin_id = $1 AND requested_section = $2 AND status = $3',
                [adminId, section, 'pending']
            );

            // Render the access denied page, and tell the page whether a request has already been sent
            res.render('admin/access-denied', { 
                section,
                requestSent: requestResult.rows.length > 0 
            });

        } catch (err) {
            console.error("Permission check error:", err);
            res.status(500).send("Server error during permission check.");
        }
    };
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
      req.session.adminId = admin.id;
      req.session.adminName = admin.name;
      req.session.adminEmail = admin.email;
      req.session.adminRole = admin.role;
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
        const mailOptions = {
            from: `"digiROCK Admin" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset Request for digiROCK',
            html: `<p>You requested a password reset. Click this link: <a href="${resetLink}">${resetLink}</a></p>`
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

// --- CHANGE PASSWORD ROUTES (FOR LOGGED-IN ADMINS) ---
router.get('/admin/change-password', requireAdminLogin, (req, res) => {
    res.render('admin/change-password', { error: null });
});

router.post('/admin/change-password', requireAdminLogin, async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const adminId = req.session.adminId;
    if (newPassword !== confirmPassword) {
        return res.render('admin/change-password', { error: 'New passwords do not match.' });
    }
    try {
        const { rows } = await pool.query('SELECT * FROM admins WHERE id = $1', [adminId]);
        const admin = rows[0];
        const passwordMatch = await bcrypt.compare(currentPassword, admin.password);
        if (!passwordMatch) {
            return res.render('admin/change-password', { error: 'Incorrect current password.' });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 600000);
        req.session.tempNewPassword = newPassword;
        req.session.otp = otp;
        req.session.otpExpires = otpExpires;
        const mailOptions = {
            from: `"digiROCK Admin" <${process.env.EMAIL_USER}>`,
            to: req.session.adminEmail,
            subject: 'Your OTP for Password Change',
            html: `<p>Your One-Time Password (OTP) is: <strong>${otp}</strong></p>`
        };
        await transporter.sendMail(mailOptions);
        res.redirect('/admin/verify-otp');
    } catch (err) {
        console.error("Change Password Error:", err);
        res.render('admin/change-password', { error: 'An error occurred.' });
    }
});

router.get('/admin/verify-otp', requireAdminLogin, (req, res) => {
    res.render('admin/verify-otp', { error: null });
});

router.post('/admin/verify-otp-and-change', requireAdminLogin, async (req, res) => {
    const { otp } = req.body;
    const adminId = req.session.adminId;
    if (otp !== req.session.otp || new Date() > new Date(req.session.otpExpires)) {
        return res.render('admin/verify-otp', { error: 'Invalid or expired OTP.' });
    }
    try {
        const newPassword = req.session.tempNewPassword;
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE admins SET password = $1 WHERE id = $2', [hashedPassword, adminId]);
        delete req.session.tempNewPassword;
        delete req.session.otp;
        delete req.session.otpExpires;
        res.redirect('/dashboard');
    } catch (err) {
        console.error("OTP Verification Error:", err);
        res.render('admin/verify-otp', { error: 'An error occurred.' });
    }
});

router.get('/dashboard', requireAdminLogin, async (req, res) => { 
  try {
    const [ donationData, ratingData, feedbackData, mailData, noticeData, recentDonationsData ] = await Promise.all([
      pool.query('SELECT COUNT(*) as count, SUM(amount) as total FROM donations'),
      pool.query('SELECT COUNT(*) as count, AVG(rating) as average FROM ratings'),
      pool.query('SELECT COUNT(*) as count FROM feedbacks'),
      pool.query('SELECT COUNT(*) as count FROM contact_messages'),
      // **MODIFIED** Dashboard notice count with timezone fix and correct logic
      pool.query("SELECT COUNT(*) as count FROM notices WHERE release_time <= NOW() AND (expire_time IS NULL OR expire_time > NOW())"),
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

// --- NOTICE MANAGEMENT ROUTES (RESTORED) ---
router.get('/admin/give-notice', requireAdminLogin, checkPermission('Notices'), (req, res) => {
  res.render('admin/give-notice');
});

router.post('/admin/give-notice', requireAdminLogin, checkPermission('Notices'), (req, res) => {
  uploadNotice(req, res, async (err) => {
    if (err) { return res.status(500).send('File upload error'); }
    const { notice_type, title, body_text, release_time, expire_time } = req.body;
    const attachmentPath = req.file ? req.file.path.replace('public', '') : null;
    const expireTimeOrNull = expire_time ? expire_time : null;
    try {
      await pool.query( 'INSERT INTO notices (notice_type, title, body_text, attachment_path, release_time, expire_time) VALUES ($1, $2, $3, $4, $5, $6)', [notice_type, title, body_text, attachmentPath, release_time, expireTimeOrNull] );
      res.redirect('/admin/notices');
    } catch (dbErr) {
      console.error(dbErr);
      res.status(500).send('Database error');
    }
  });
});

router.get('/admin/notices', requireAdminLogin, checkPermission('Notices'), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM notices ORDER BY release_time DESC');
    res.render('admin/admin-notices', { notices: rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

router.get('/admin/notices/edit/:id', requireAdminLogin, checkPermission('Notices'), async (req, res) => {
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

router.post('/admin/notices/update/:id', requireAdminLogin, checkPermission('Notices'), (req, res) => {
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
      await pool.query( `UPDATE notices SET notice_type = $1, title = $2, body_text = $3, attachment_path = $4, release_time = $5, expire_time = $6 WHERE id = $7`, [notice_type, title, body_text, attachmentPath, release_time, expireTimeOrNull, id] );
      res.redirect('/admin/notices');
    } catch (dbErr) {
      console.error(dbErr);
      res.status(500).send('Database error');
    }
  });
});

router.post('/admin/notices/delete/:id', requireAdminLogin, checkPermission('Notices'), async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM notices WHERE id = $1', [id]);
        res.redirect('/admin/notices');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// --- OTHER PROTECTED ROUTES WITH PERMISSION CHECKS ---
router.get('/admin/donations', requireAdminLogin, checkPermission('Donations'), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM donations ORDER BY created_at DESC');
    res.render('admin/admin-donations', { donations: rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

router.get('/admin/feedbacks', requireAdminLogin, checkPermission('Feedbacks'), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM feedbacks ORDER BY created_at DESC');
    res.render('admin/admin-feedbacks', { feedbacks: rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

router.get('/admin/ratings', requireAdminLogin, checkPermission('Ratings'), async (req, res) => {
    const timeFilter = req.query.time_filter || 'all';
    let whereClause = '';
    switch (timeFilter) {
        case 'this_year': whereClause = `WHERE date_trunc('year', created_at) = date_trunc('year', CURRENT_TIMESTAMP)`; break;
        case 'this_month': whereClause = `WHERE date_trunc('month', created_at) = date_trunc('month', CURRENT_TIMESTAMP)`; break;
        case 'this_week': whereClause = `WHERE date_trunc('week', created_at) = date_trunc('week', CURRENT_TIMESTAMP)`; break;
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

router.get('/admin/mails', requireAdminLogin, checkPermission('Mails'), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM contact_messages ORDER BY created_at DESC');
    res.render('admin/admin-mails', { messages: rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// --- ACCESS REQUEST ROUTES ---
router.post('/admin/request-access', requireAdminLogin, async (req, res) => {
    const { section } = req.body;
    const adminId = req.session.adminId;
    const adminName = req.session.adminName;
    const adminRole = req.session.adminRole;

    try {
        const existingRequest = await pool.query(
            'SELECT * FROM access_requests WHERE admin_id = $1 AND requested_section = $2 AND status = $3',
            [adminId, section, 'pending']
        );

        if (existingRequest.rows.length === 0) {
            await pool.query(
                'INSERT INTO access_requests (admin_id, admin_name, admin_role, requested_section) VALUES ($1, $2, $3, $4)',
                [adminId, adminName, adminRole, section]
            );
        }
        res.render('admin/access-denied', { section, requestSent: true });
    } catch (err) {
        console.error("Error creating access request:", err);
        res.status(500).send("Server error.");
    }
});

router.get('/admin/manage-requests', requireAdminLogin, requireOwner, async (req, res) => {
    try {
        const { rows } = await pool.query("SELECT * FROM access_requests WHERE status = 'pending' ORDER BY created_at DESC");
        res.render('admin/manage-requests', { requests: rows });
    } catch (err) {
        console.error("Error fetching access requests:", err);
        res.status(500).send("Server error.");
    }
});

router.post('/admin/approve-request/:id', requireAdminLogin, requireOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const requestResult = await pool.query("SELECT * FROM access_requests WHERE id = $1", [id]);
        if (requestResult.rows.length === 0) {
            return res.status(404).send("Request not found.");
        }
        const request = requestResult.rows[0];
        await pool.query( "INSERT INTO admin_permissions (admin_id, allowed_section) VALUES ($1, $2) ON CONFLICT DO NOTHING", [request.admin_id, request.requested_section] );
        await pool.query("UPDATE access_requests SET status = 'approved' WHERE id = $1", [id]);
        res.redirect('/admin/manage-requests');
    } catch (err) {
        console.error("Error approving request:", err);
        res.status(500).send("Server error.");
    }
});

router.post('/admin/deny-request/:id', requireAdminLogin, requireOwner, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query("UPDATE access_requests SET status = 'denied' WHERE id = $1", [id]);
        res.redirect('/admin/manage-requests');
    } catch (err) {
        console.error("Error denying request:", err);
        res.status(500).send("Server error.");
    }
});

// --- ADMIN MANAGEMENT ROUTES (PROTECTED) ---
router.get('/admin/manage-admins', requireAdminLogin, requireOwner, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, name, email, role FROM admins ORDER BY name');
    res.render('admin/manage-admins', { 
      admins: rows,
      currentAdminId: req.session.adminId
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

router.post('/admin/add-admin', requireAdminLogin, requireOwner, async (req, res) => {
  const { name, email, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query( 'INSERT INTO admins (name, email, password, role) VALUES ($1, $2, $3, $4)', [name, email, hashedPassword, role] );
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

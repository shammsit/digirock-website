const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
require('dotenv').config();

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

const requireAdminLogin = (req, res, next) => {
    if (!req.session.isAdmin) { return res.redirect('/monitor_admin'); }
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
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
      req.session.adminName = admin.name;
      res.redirect('/dashboard');
    } else {
      res.redirect('/monitor_admin');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error during login.');
  }
});

router.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

router.get('/dashboard', requireAdminLogin, (req, res) => { 
  res.render('admin/dashboard', { adminName: req.session.adminName }); 
});

// --- NOTICE MANAGEMENT ROUTES ---
// ... (all your existing notice, ratings, mail, feedback, and donation routes are here)
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
        await pool.qu

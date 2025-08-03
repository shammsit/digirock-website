const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Multer config for notice attachments
const noticeStorage = multer.diskStorage({
  destination: './public/notices/',
  filename: function(req, file, cb){
    cb(null, 'notice-' + Date.now() + path.extname(file.originalname));
  }
});
const uploadNotice = multer({ storage: noticeStorage }).single('attachment');

// Middleware to check admin login & permissions (stub, should be imported or redefined)
const requireAdminLogin = (req, res, next) => {
  if (!req.session.isAdmin) return res.redirect('/monitor_admin');
  next();
};
// Dummy checkPermission middleware, replace or import your actual
const checkPermission = (section) => (req, res, next) => next();

// Helper function to convert local datetime string to UTC for DB
function toUTC(dateStr) {
  if (!dateStr) return null;
  const dt = new Date(dateStr);
  return new Date(dt.getTime() - dt.getTimezoneOffset()*60000).toISOString().slice(0,19).replace('T', ' ');
}

// --- Notice routes ---

// Show all notices (admin view)
router.get('/admin/notices', requireAdminLogin, checkPermission('Notices'), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM notices ORDER BY release_time DESC');
    res.render('admin/admin-notices', { notices: rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// Form to add new notice
router.get('/admin/give-notice', requireAdminLogin, checkPermission('Notices'), (req, res) => {
  res.render('admin/give-notice');
});

// Handle new notice POST with UTC conversion
router.post('/admin/give-notice', requireAdminLogin, checkPermission('Notices'), (req, res) => {
  uploadNotice(req, res, async (err) => {
    if (err) return res.status(500).send('File upload error');
    const { notice_type, title, body_text, release_time, expire_time } = req.body;
    const attachmentPath = req.file ? req.file.path.replace('public', '') : null;
    const releaseTimeUTC = toUTC(release_time);
    const expireTimeUTC = toUTC(expire_time);
    try {
      await pool.query(
        `INSERT INTO notices (notice_type, title, body_text, attachment_path, release_time, expire_time) VALUES ($1, $2, $3, $4, $5, $6)`,
        [notice_type, title, body_text, attachmentPath, releaseTimeUTC, expireTimeUTC]
      );
      res.redirect('/admin/notices');
    } catch (dbErr) {
      console.error(dbErr);
      res.status(500).send('Database error');
    }
  });
});

// Form to edit a notice
router.get('/admin/notices/edit/:id', requireAdminLogin, checkPermission('Notices'), async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query('SELECT * FROM notices WHERE id = $1', [id]);
    if (rows.length === 0) return res.redirect('/admin/notices');
    res.render('admin/edit-notice', { notice: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Handle notice update with UTC conversion
router.post('/admin/notices/update/:id', requireAdminLogin, checkPermission('Notices'), (req, res) => {
  uploadNotice(req, res, async (err) => {
    if (err) return res.status(500).send('File upload error');
    const { id } = req.params;
    const { notice_type, title, body_text, release_time, expire_time, current_attachment } = req.body;
    let attachmentPath = current_attachment;
    if (req.file) attachmentPath = req.file.path.replace('public', '');
    const releaseTimeUTC = toUTC(release_time);
    const expireTimeUTC = toUTC(expire_time);
    try {
      await pool.query(
        `UPDATE notices SET notice_type=$1, title=$2, body_text=$3, attachment_path=$4, release_time=$5, expire_time=$6 WHERE id=$7`,
        [notice_type, title, body_text, attachmentPath, releaseTimeUTC, expireTimeUTC, id]
      );
      res.redirect('/admin/notices');
    } catch (dbErr) {
      console.error(dbErr);
      res.status(500).send('Database error');
    }
  });
});

// Delete notice
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

module.exports = router;

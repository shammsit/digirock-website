// noticesroute.js
const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const { requireAdminLogin, setPermissionSection, checkPermission } = require('../middleware/auth');
require('dotenv').config();

// --- Database Pool ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
pool.on('connect', (client) => {
  client.query("SET TIME ZONE 'Asia/Kolkata'");
});

const permissionCheck = checkPermission(pool);

// Multer setup for notice attachments
const noticeStorage = multer.diskStorage({
  destination: './public/notices/',
  filename: (req, file, cb) => {
    cb(null, 'notice-' + Date.now() + path.extname(file.originalname));
  },
});
const uploadNotice = multer({ storage: noticeStorage }).single('attachment');

// Helper function to convert local datetime to UTC ISO string
function toUTC(dateStr) {
  if (!dateStr) return null;
  const dt = new Date(dateStr);
  return dt.toISOString();
}

// Notice routes
const noticePermission = [setPermissionSection('Notices'), permissionCheck];

router.get('/admin/give-notice', requireAdminLogin, noticePermission, (req, res) => {
  res.render('admin/give-notice', { adminRole: req.session.adminRole });
});

router.post('/admin/give-notice', requireAdminLogin, noticePermission, (req, res) => {
  uploadNotice(req, res, async (err) => {
    if (err) return res.status(500).send('File upload error');
    const { notice_type, title, body_text, release_time, expire_time } = req.body;
    const attachmentPath = req.file ? req.file.path.replace('public', '') : null;
    const releaseTimeUTC = toUTC(release_time);
    const expireTimeUTC = toUTC(expire_time);
    try {
      await pool.query(
        'INSERT INTO notices (notice_type, title, body_text, attachment_path, release_time, expire_time) VALUES ($1,$2,$3,$4,$5,$6)',
        [notice_type, title, body_text, attachmentPath, releaseTimeUTC, expireTimeUTC]
      );
      res.redirect('/admin/notices');
    } catch (dbErr) {
      console.error(dbErr);
      res.status(500).send('Database error');
    }
  });
});

router.get('/admin/notices', requireAdminLogin, noticePermission, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM notices ORDER BY release_time DESC');
    res.render('admin/admin-notices', { notices: rows, adminRole: req.session.adminRole });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

router.get('/admin/notices/edit/:id', requireAdminLogin, noticePermission, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query('SELECT * FROM notices WHERE id = $1', [id]);
    if (rows.length === 0) return res.redirect('/admin/notices');
    res.render('admin/edit-notice', { notice: rows[0], adminRole: req.session.adminRole });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

router.post('/admin/notices/update/:id', requireAdminLogin, noticePermission, (req, res) => {
  uploadNotice(req, res, async (err) => {
    const { id } = req.params;
    if (err) return res.status(500).send('File upload error');
    const { notice_type, title, body_text, release_time, expire_time, current_attachment } = req.body;
    let attachmentPath = current_attachment;
    if (req.file) attachmentPath = req.file.path.replace('public', '');
    const releaseTimeUTC = toUTC(release_time);
    const expireTimeUTC = toUTC(expire_time);
    try {
      await pool.query(
        'UPDATE notices SET notice_type=$1, title=$2, body_text=$3, attachment_path=$4, release_time=$5, expire_time=$6 WHERE id=$7',
        [notice_type, title, body_text, attachmentPath, releaseTimeUTC, expireTimeUTC, id]
      );
      res.redirect('/admin/notices');
    } catch (dbErr) {
      console.error(dbErr);
      res.status(500).send('Database error');
    }
  });
});

router.post('/admin/notices/delete/:id', requireAdminLogin, noticePermission, async (req, res) => {
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
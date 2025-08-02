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

// **MODIFIED DASHBOARD ROUTE TO FETCH DATA**
router.get('/dashboard', requireAdminLogin, async (req, res) => { 
  try {
    // Run all database queries concurrently for speed
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

module.exports = router;

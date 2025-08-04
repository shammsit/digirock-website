const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Middleware to ensure only the owner can access these routes
const requireOwner = (req, res, next) => {
    // This checks if the logged-in admin has the role of 'owner'
    if (req.session.isAdmin && req.session.adminRole === 'owner') {
        next();
    } else {
        res.status(403).send('Forbidden: You do not have permission for this action.');
    }
};

// Route to display the social media management page
router.get('/admin/handle-social-media', requireOwner, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM social_media_links ORDER BY platform_name');
    res.render('admin/handle-social-media', { links: rows, adminRole: req.session.adminRole });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// Route to add a new social media link
router.post('/admin/social-media/add', requireOwner, async (req, res) => {
  const { platform_name, platform_key, link_url } = req.body;
  try {
    await pool.query(
      'INSERT INTO social_media_links (platform_name, platform_key, link_url) VALUES ($1, $2, $3)',
      [platform_name, platform_key, link_url]
    );
    res.redirect('/admin/handle-social-media');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Route to delete a social media link
router.post('/admin/social-media/delete/:id', requireOwner, async (req, res) => {
  try {
    await pool.query('DELETE FROM social_media_links WHERE id = $1', [req.params.id]);
    res.redirect('/admin/handle-social-media');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

module.exports = router;
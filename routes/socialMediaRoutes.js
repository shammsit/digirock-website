const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const { requireAdminLogin, setPermissionSection, checkPermission } = require('../middleware/auth');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const permissionCheck = checkPermission(pool);

// Define the middleware array to be used for all social media routes
const socialMediaPermission = [requireAdminLogin, setPermissionSection('Social Media'), permissionCheck];

// Route to display the social media management page
router.get('/admin/handle-social-media', socialMediaPermission, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM social_media_links ORDER BY platform_name');
    res.render('admin/handle-social-media', { links: rows, adminRole: req.session.adminRole });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// Route to add a new social media link
router.post('/admin/social-media/add', socialMediaPermission, async (req, res) => {
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
router.post('/admin/social-media/delete/:id', socialMediaPermission, async (req, res) => {
  try {
    await pool.query('DELETE FROM social_media_links WHERE id = $1', [req.params.id]);
    res.redirect('/admin/handle-social-media');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

module.exports = router;
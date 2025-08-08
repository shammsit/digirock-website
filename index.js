const express = require('express');
const session = require('express-session');
const dotenv = require('dotenv');
const path = require('path');
const { Pool } = require('pg');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'a-very-secret-key-that-is-long-and-random',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using HTTPS
}));

app.use(async (req, res, next) => {
  try {
    const result = await pool.query('SELECT platform_name, platform_key, link_url FROM social_media_links ORDER BY platform_name');
    res.locals.socialLinks = result.rows;
    next();
  } catch (err) {
    console.error('Failed to fetch social links for layout:', err);
    res.locals.socialLinks = [];
    next();
  }
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Import route files
const homeRoutes = require('./routes/homeRoutes');
const adminRoutes = require('./routes/adminRoutes');
const noticeRoutes = require('./routes/noticesroute');
const socialMediaRoutes = require('./routes/socialMediaRoutes');
const userRoutes = require('./routes/userRoutes'); // <-- ADDED

// Register routes
app.use('/', homeRoutes);
app.use('/', adminRoutes);
app.use('/', noticeRoutes);
app.use('/', socialMediaRoutes);
app.use('/', userRoutes); // <-- ADDED

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});

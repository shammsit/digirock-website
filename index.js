const express = require('express');
const session = require('express-session');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware to parse URL-encoded and JSON bodies
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session setup
app.use(session({
  secret: process.env.SESSION_SECRET || 'a-very-secret-key-that-is-long-and-random',
  resave: false,
  saveUninitialized: true
}));

// Set up view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Import route files
const homeRoutes = require('./routes/homeRoutes');
const adminRoutes = require('./routes/adminRoutes');
const noticeRoutes = require('./routes/noticesroute');
const socialMediaRoutes = require('./routes/socialMediaRoutes'); // <-- ADDED

// Register routes
app.use('/', homeRoutes);
app.use('/', adminRoutes);
app.use('/', noticeRoutes);
app.use('/', socialMediaRoutes); // <-- ADDED

// Start server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
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
const homeRoutes = require('./routes/homeroute');    // Adjust filename as needed
const adminRoutes = require('./routes/adminroute');   // Your admin routes (excluding notices)
const noticeRoutes = require('./routes/noticesroute'); // If you split notices

// Register routes
app.use('/', homeRoutes);
app.use('/', adminRoutes);
app.use('/', noticeRoutes); // optional if notices in separate file

// Start server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});

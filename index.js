// Import packages
const express = require('express');
const session = require('express-session');

// Import route files
const homeRoutes = require('./routes/homeRoutes');
const adminRoutes = require('./routes/adminRoutes');

// Create the app
const app = express();
const port = 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'a-very-secret-key-that-is-long-and-random',
  resave: false,
  saveUninitialized: true
}));
app.set('view engine', 'ejs');
app.use(express.static('public'));

// Use the route files
app.use('/', homeRoutes);
app.use('/', adminRoutes);

// START THE SERVER
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
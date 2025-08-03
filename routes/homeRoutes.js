const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const Razorpay = require('razorpay');
const crypto = require('crypto');
require('dotenv').config();

// --- DATABASE POOL ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// --- INITIALIZE RAZORPAY ---
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// --- MULTER FILE UPLOAD CONFIGURATION ---
const contactStorage = multer.diskStorage({
  destination: './public/uploads/',
  filename: function(req, file, cb){
    cb(null, 'contact-' + Date.now() + path.extname(file.originalname));
  }
});
const uploadContact = multer({ storage: contactStorage }).single('attachment');


// --- MAIN PAGE ROUTES ---
router.get('/', async (req, res) => {
    try {
      const summaryResult = await pool.query('SELECT rating, COUNT(*) as count FROM ratings GROUP BY rating ORDER BY rating DESC;');
      const chartData = {
        labels: summaryResult.rows.map(row => `${row.rating} Star`),
        data: summaryResult.rows.map(row => row.count)
      };
      res.render('home/home', { chartData: JSON.stringify(chartData) });
    } catch (err) {
      console.error(err);
      res.render('home/home', { chartData: '{}' });
    }
});
router.get('/contact', (req, res) => { res.render('home/contact'); });
router.get('/terms', (req, res) => { res.render('home/terms'); });
router.get('/login', (req, res) => { res.render('home/login'); });
router.get('/signup', (req, res) => { res.render('home/signup'); });
router.get('/donate', (req, res) => { res.render('home/donate'); });
router.get('/feedback', (req, res) => { res.render('home/feedback'); });
router.get('/rate-us', (req, res) => { res.render('home/rate-us'); });
router.get('/thank-you', (req, res) => { res.render('home/thank-you'); });

router.get('/payment-success', async (req, res) => {
  const paymentId = req.query.id;
  if (!paymentId) {
    return res.redirect('/');
  }
  try {
    const { rows } = await pool.query('SELECT * FROM donations WHERE payment_id = $1', [paymentId]);
    if (rows.length > 0) {
      res.render('home/payment-success', { donation: rows[0] });
    } else {
      res.status(404).send('Payment details not found.');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


// --- FORM SUBMISSION & PAYMENT ROUTES ---

router.post('/submit-rating', async (req, res) => {
  const { rating, message } = req.body;
  try {
    await pool.query('INSERT INTO ratings (rating, message) VALUES ($1, $2)', [rating, message]);
    res.redirect('/thank-you');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

router.post('/submit-feedback', async (req, res) => {
  const { name, feedbackType, message } = req.body;
  try {
    const finalName = name || null;
    await pool.query(
      'INSERT INTO feedbacks (name, feedback_type, message) VALUES ($1, $2, $3)',
      [finalName, feedbackType, message]
    );
    res.redirect('/thank-you');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// **CORRECTED** Public Noticeboard Page with Timezone Fix
router.get('/noticeboard', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM notices 
       WHERE release_time <= NOW()
       AND (expire_time IS NULL OR expire_time > NOW()) 
       ORDER BY release_time DESC`
    );
    res.render('home/noticeboard', { notices: rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

router.post('/submit-contact', (req, res) => {
  uploadContact(req, res, async (err) => {
    if(err){
      console.error(err);
      return res.status(500).send('File upload error');
    }
    const { name, email, subject, message } = req.body;
    const attachmentPath = req.file ? req.file.path.replace('public', '') : null;
    try {
      await pool.query(
        'INSERT INTO contact_messages (name, email, subject, message, attachment_path) VALUES ($1, $2, $3, $4, $5)',
        [name, email, subject, message, attachmentPath]
      );
      res.redirect('/thank-you');
    } catch (dbErr) {
      console.error(dbErr);
      res.status(500).send('Database error');
    }
  });
});

// --- RAZORPAY PAYMENT ROUTES ---

router.post('/create-order', express.json(), async (req, res) => {
    const { amount, name, email } = req.body;
    const numericAmount = Number(amount);
    if (isNaN(numericAmount) || numericAmount < 1) {
        return res.status(400).send('Invalid amount.');
    }
    const options = {
        amount: numericAmount * 100,
        currency: 'INR',
        receipt: `receipt_order_${new Date().getTime()}`,
    };
    try {
        const order = await razorpay.orders.create(options);
        res.json({
            key_id: process.env.RAZORPAY_KEY_ID,
            id: order.id,
            amount: order.amount
        });
    } catch (error) {
        console.error('Razorpay order creation error:', error);
        res.status(500).send({ error: 'Error creating payment order.', details: error.message });
    }
});

router.post('/verify-payment', express.json(), async (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, name, email, amount } = req.body;
    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSignature = crypto
        .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(body.toString())
        .digest('hex');
    if (expectedSignature === razorpay_signature) {
        try {
            const numericAmount = Number(amount);
            await pool.query(
                `INSERT INTO donations (name, email, amount, payment_id)
                 VALUES ($1, $2, $3, $4)`,
                [name, email, numericAmount, razorpay_payment_id]
            );
            res.status(200).send('Payment verified successfully.');
        } catch (dbErr) {
            console.error('Database error after payment verification:', dbErr);
            res.status(500).send('Database error.');
        }
    } else {
        res.status(400).send('Invalid signature. Payment verification failed.');
    }
});


module.exports = router;

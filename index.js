require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

// Environment variables
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_PUBLIC;
const JWT_SECRET = process.env.JWT_SECRET;
const API_KEY = process.env.API_KEY;

// Initialize Supabase client
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// API Key middleware
function apiKeyMiddleware(req, res, next) {
  if (req.path === '/') return next(); // Allow health check
  const key = req.headers['x-api-key'];
  if (!key || key !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or missing API key.' });
  }
  next();
}
app.use(apiKeyMiddleware);

app.get('/', (req, res) => {
  res.send('Hello Universe, Annie are you Okay?!');
});

const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // limit each IP to 5 requests per windowMs
  message: { error: 'Too many requests, please try again later.' }
});

app.post('/register', authLimiter, async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body;
    if (!name || !email || !mobile || !password) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    // Check if user already exists (by email or mobile)
    const { data: existing, error: findError } = await supabase
      .from('restaurants')
      .select('id')
      .or(`email.eq.${email},mobile.eq.${mobile}`);
    if (findError) throw findError;
    if (existing && existing.length > 0) {
      return res.status(409).json({ error: 'User with this email or mobile already exists.' });
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, 10);

    // Insert new user
    const { data, error } = await supabase
      .from('restaurants')
      .insert([{ name, email, mobile, password_hash }])
      .select();
    if (error) throw error;

    const user = data[0];
    // Create JWT
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed.' });
  }
});

app.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    // Find user by email
    const { data, error } = await supabase
      .from('restaurants')
      .select('id, name, email, password_hash')
      .eq('email', email)
      .single();
    if (error || !data) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Compare password
    const valid = await bcrypt.compare(password, data.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Create JWT
    const token = jwt.sign({ id: data.id, email: data.email, name: data.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed.' });
  }
});

app.post('/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required.' });
    }

    // Find user by email
    const { data, error } = await supabase
      .from('restaurants')
      .select('id, email')
      .eq('email', email)
      .single();
    if (error || !data) {
      // Always return success for security
      return res.json({ message: 'If the email exists, reset instructions have been sent.' });
    }

    // Generate reset token (JWT, short expiry)
    const resetToken = jwt.sign({ id: data.id, email: data.email }, JWT_SECRET, { expiresIn: '15m' });
    // Mock sending email: log the reset link
    console.log(`Password reset link: https://your-app/reset-password?token=${resetToken}`);

    res.json({ message: 'If the email exists, reset instructions have been sent.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Password reset failed.' });
  }
});

app.post('/verify-token', authLimiter, (req, res) => {
  try {
    let token = req.body.token;
    // Prefer Authorization header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }
    if (!token) {
      return res.status(400).json({ error: 'Token is required.' });
    }
    jwt.verify(token, JWT_SECRET);
    res.json({ valid: true });
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token.' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  // Log error (no sensitive data)
  if (err) {
    console.error('Error:', err.message);
  }
  res.status(err.status || 500).json({ error: err.message || 'Internal server error.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 
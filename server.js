// server.js
const express = require('express');

const app = express();
app.use(express.json());

// --- API 1: Health Check ---
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// --- API 2: Echo (test POST body) ---
app.post('/echo', (req, res) => {
  res.json({ received: req.body });
});

// --- API 3: Random Number Generator ---
app.get('/random', (req, res) => {
  const randomNumber = Math.floor(Math.random() * 1000);
  res.json({ randomNumber });
});

// --- Start Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

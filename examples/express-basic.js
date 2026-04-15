/*
 * Basic integration example.
 *
 * Start:  node examples/express-basic.js
 * Test:   curl "http://localhost:3000/search?q=' OR 1=1--"
 */

const express = require('express');
const shieldwall = require('../src/index');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(shieldwall({
  mode: 'block',
  logLevel: 'info',
  rateLimit: { windowMs: 60_000, max: 100 },
  bruteForce: { maxAttempts: 5, sensitivePaths: ['/login'] },
  excludePaths: ['/health'],
}));

app.get('/', (req, res) => {
  res.json({
    message: '🛡️ ShieldWall Protected API',
    endpoints: {
      '/search?q=...': 'Search (try injection here)',
      '/page?file=..': 'Page loader (try traversal here)',
      '/comment':      'POST a comment (try XSS here)',
      '/exec?cmd=..':  'Command test (try cmdi here)',
      '/login':        'POST login (brute-force protected)',
      '/health':       'Health check (excluded from WAF)',
    },
  });
});

app.get('/search', (req, res) => res.json({ results: [], query: req.query.q }));
app.get('/page', (req, res) => res.json({ page: req.query.file }));
app.post('/comment', (req, res) => res.json({ text: req.body?.text }));
app.get('/exec', (req, res) => res.json({ cmd: req.query.cmd }));
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === 'admin' && password === 'admin') {
    return res.json({ status: 'ok', token: 'demo-token' });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 Server at http://localhost:${PORT}`);
  console.log('🛡️  ShieldWall active (block mode)\n');
  console.log('Try:');
  console.log(`  curl "http://localhost:${PORT}/search?q=' OR 1=1--"`);
  console.log(`  curl "http://localhost:${PORT}/search?q=<script>alert(1)</script>"`);
  console.log(`  curl "http://localhost:${PORT}/page?file=../../../../etc/passwd"`);
  console.log(`  curl "http://localhost:${PORT}/exec?cmd=;cat /etc/passwd"`);
  console.log(`  curl "http://localhost:${PORT}/search?q=hello" (should pass)\n`);
});

/*
 * Full-featured example with dashboard, honeypot, brute-force, and anomaly detection.
 *
 * Start:  node examples/express-dashboard.js
 * App:    http://localhost:3000
 * Dashboard: http://localhost:9090
 */

const express = require('express');
const shieldwall = require('../src/index');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const waf = shieldwall({
  mode: 'block',
  logLevel: 'info',

  dashboard: { port: 9090, host: 'localhost' },

  rateLimit: { windowMs: 60_000, max: 50 },

  bruteForce: {
    maxAttempts: 5,
    windowMs: 15 * 60_000,
    sensitivePaths: ['/login', '/api/auth'],
  },

  honeypot: true,

  headers: {
    hsts: { maxAge: 31536000, includeSubDomains: true },
    frameOptions: 'DENY',
  },
});

app.use(waf);

// forward threat events to any external system
waf.on('threat', (event) => {
  // example: send to Slack, Discord, webhook, SIEM pipeline...
  // console.log('Threat:', JSON.stringify(event, null, 2));
});

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>ShieldWall Demo</title></head>
    <body style="font-family:sans-serif;max-width:600px;margin:40px auto;padding:20px">
      <h1>🛡️ ShieldWall Demo</h1>
      <p>This page is protected. Open the <a href="http://localhost:9090" target="_blank">Dashboard</a> and try sending attacks.</p>
      <h3>Test endpoints:</h3>
      <ul>
        <li><a href="/search?q=test">/search?q=test</a> (normal)</li>
        <li><a href="/search?q=' OR 1=1--">/search?q=' OR 1=1--</a> (SQLi)</li>
        <li><a href="/page?file=../../../../etc/passwd">/page?file=../../../../etc/passwd</a> (traversal)</li>
      </ul>
      <form action="/login" method="POST">
        <h3>Login (brute-force protected):</h3>
        <input name="username" placeholder="username"><br><br>
        <input name="password" type="password" placeholder="password"><br><br>
        <button type="submit">Login</button>
      </form>
    </body></html>
  `);
});

app.get('/search', (req, res) => res.json({ results: [], query: req.query.q }));
app.get('/page', (req, res) => res.json({ page: req.query.file }));
app.get('/api/data', (req, res) => res.json({ data: [1, 2, 3] }));

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === 'demo' && password === 'demo') {
    return res.json({ status: 'ok', token: 'demo-jwt-token' });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 App:       http://localhost:${PORT}`);
  console.log(`📊 Dashboard: http://localhost:9090`);
  console.log('🛡️  ShieldWall active — send attacks and watch the dashboard\n');
});

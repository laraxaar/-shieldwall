'use strict';

const { SmartAnomalyDetector } = require('../src/modules/smart-anomaly');
const path = require('path');

const detector = new SmartAnomalyDetector(path.join(__dirname, '..', 'rules'));

console.log('=== Smart Anomaly Detection Demo ===\n');

console.log(`Loaded ${detector.rules.length} rules`);
console.log(`Categories: ${Array.from(detector.categoryProfiles.keys()).join(', ')}\n`);

const testCases = [
  {
    name: 'Normal request',
    req: {
      ip: '1.2.3.4',
      method: 'GET',
      url: '/api/users',
      path: '/api/users',
      query: { page: '1' },
      body: '',
      headers: { 'accept': 'application/json', 'user-agent': 'Mozilla/5.0' },
      cookies: {},
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      rawUrl: '/api/users?page=1',
    },
  },
  {
    name: 'SQL Injection attempt',
    req: {
      ip: '5.6.7.8',
      method: 'GET',
      url: '/search?q=1\' OR \'1\'=\'1',
      path: '/search',
      query: { q: "1' OR '1'='1" },
      body: '',
      headers: { 'accept': 'text/html' },
      cookies: {},
      userAgent: 'Mozilla/5.0',
      rawUrl: "/search?q=1' OR '1'='1'",
    },
  },
  {
    name: 'XSS attempt',
    req: {
      ip: '9.10.11.12',
      method: 'POST',
      url: '/comment',
      path: '/comment',
      query: {},
      body: '<script>alert(document.cookie)</script>',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      cookies: {},
      userAgent: 'Mozilla/5.0',
      rawUrl: '/comment',
    },
  },
  {
    name: 'SSRF attempt (novel pattern)',
    req: {
      ip: '13.14.15.16',
      method: 'GET',
      url: '/fetch?url=http://127.0.0.1:22/',
      path: '/fetch',
      query: { url: 'http://127.0.0.1:22/' },
      body: '',
      headers: {},
      cookies: {},
      userAgent: 'curl/7.68.0',
      rawUrl: '/fetch?url=http://127.0.0.1:22/',
    },
  },
  {
    name: 'Mass Assignment attempt',
    req: {
      ip: '17.18.19.20',
      method: 'POST',
      url: '/api/users',
      path: '/api/users',
      query: {},
      body: '{"username": "hacker", "isAdmin": true, "role": "admin"}',
      headers: { 'content-type': 'application/json' },
      cookies: {},
      userAgent: 'Mozilla/5.0',
      rawUrl: '/api/users',
    },
  },
  {
    name: 'Encoded attack (evasion)',
    req: {
      ip: '21.22.23.24',
      method: 'GET',
      url: '/search?q=%253C%2573%2563%2572%2569%2570%2574%253E',
      path: '/search',
      query: { q: '%253C%2573%2563%2572%2569%2570%2574%253E' },
      body: '',
      headers: {},
      cookies: {},
      userAgent: 'Mozilla/5.0',
      rawUrl: '/search?q=%253C%2573%2563%2572%2569%2570%2574%253E',
    },
  },
];

for (const test of testCases) {
  console.log(`\n--- ${test.name} ---`);
  const result = detector.analyze(test.req);

  if (result.detected) {
    console.log(`❌ ANOMALY DETECTED`);
    console.log(`   Score: ${result.score.toFixed(1)} (${result.severity})`);
    console.log(`   Description: ${result.description}`);
    console.log(`   Categories: ${Object.keys(result.categoryScores || {}).join(', ') || 'none'}`);

    if (result.analysis?.novelIndicators?.length > 0) {
      console.log(`   Novel indicators: ${result.analysis.novelIndicators.join(', ')}`);
    }

    if (result.analysis?.temporalAnomaly) {
      console.log(`   Temporal: ${result.analysis.temporalAnomaly.type}`);
    }
  } else {
    console.log(`✅ Clean (score: ${result.score.toFixed(1)})`);
  }
}

console.log('\n\n=== Summary ===');
console.log('Smart anomaly detection analyzes request features against rule profiles');
console.log('to detect attacks even when exact patterns do not match.');
console.log('Zero-day and evasion attempts are caught via fuzzy matching and behavioral analysis.');

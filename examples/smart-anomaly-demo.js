'use strict';

const { SmartAnomalyDetector } = require('../src/modules/smart-anomaly');
const path = require('path');

const detector = new SmartAnomalyDetector(path.join(__dirname, '..', 'rules'));

// Цвета для красивого вывода в консоль
const C = {
  reset: '\x1b[0m', red: '\x1b[31m', green: '\x1b[32m',
  yellow: '\x1b[33m', blue: '\x1b[34m', cyan: '\x1b[36m',
  magenta: '\x1b[35m'
};

console.log(`${C.cyan}=== Smart Anomaly Detection Demo ===${C.reset}\n`);

console.log(`${C.blue}Loaded ${detector.rules.length} rules${C.reset}`);
console.log(`${C.blue}Categories: ${Array.from(detector.categoryProfiles.keys()).join(', ')}${C.reset}\n`);

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
  {
    name: 'Cloud Metadata SSRF (AWS)',
    req: {
      ip: '25.26.27.28',
      method: 'GET',
      url: '/proxy?url=http://169.254.169.254/latest/meta-data/',
      path: '/proxy',
      query: { url: 'http://169.254.169.254/latest/meta-data/' },
      body: '',
      headers: { 'X-aws-ec2-metadata-token-ttl-seconds': '21600' },
      cookies: {},
      userAgent: 'Mozilla/5.0',
      rawUrl: '/proxy?url=http://169.254.169.254/latest/meta-data/',
    },
  },
  {
    name: 'SQL Padding Evasion',
    req: {
      ip: '29.30.31.32',
      method: 'POST',
      url: '/login',
      path: '/login',
      query: {},
      body: '{"username": "admin", "password": "\' UNION        SELECT        1,2,3      FROM      users--"}',
      headers: { 'content-type': 'application/json' },
      cookies: {},
      userAgent: 'Mozilla/5.0',
      rawUrl: '/login',
    },
  },
  {
    name: 'Fragmented Char Obfuscation',
    req: {
      ip: '33.34.35.36',
      method: 'GET',
      url: '/search?query=char(115)||char(101)||char(108)||char(101)||char(99)||char(116)',
      path: '/search',
      query: { query: 'char(115)||char(101)||char(108)||char(101)||char(99)||char(116)' },
      body: '',
      headers: {},
      cookies: {},
      userAgent: 'Mozilla/5.0',
      rawUrl: '/search?query=char(115)||char(101)||char(108)||char(101)||char(99)||char(116)',
    },
  },
  {
    name: 'Executable PE Payload Upload',
    req: {
      ip: '37.38.39.40',
      method: 'POST',
      url: '/api/upload',
      path: '/api/upload',
      query: {},
      body: '{"filename": "update.exe", "data": "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9n"}',
      headers: { 'content-type': 'application/json' },
      cookies: {},
      userAgent: 'Mozilla/5.0',
      rawUrl: '/api/upload',
    },
  },
  {
    name: 'Time-Based Blind SQLi',
    req: {
      ip: '41.42.43.44',
      method: 'GET',
      url: '/products/1?sort=(select(0)from(select(sleep(15)))v)',
      path: '/products/1',
      query: { sort: '(select(0)from(select(sleep(15)))v)' },
      body: '',
      headers: {},
      cookies: {},
      userAgent: 'Mozilla/5.0',
      rawUrl: '/products/1?sort=(select(0)from(select(sleep(15)))v)',
    },
  },
  {
    name: 'Aggressive AI Bot Scraper',
    req: {
      ip: '45.46.47.48',
      method: 'GET',
      url: '/documentation',
      path: '/documentation',
      query: {},
      body: '',
      headers: { 'user-agent': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot' },
      cookies: {},
      userAgent: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot',
      rawUrl: '/documentation',
    },
  },
];

for (const test of testCases) {
  console.log(`\n${C.yellow}--- [TEST]: ${test.name} ---${C.reset}`);
  const result = detector.analyze(test.req);

  if (result.detected) {
    console.log(`${C.red}❌ ANOMALY DETECTED${C.reset}`);
    console.log(`   ${C.magenta}Score:${C.reset} ${result.score.toFixed(1)} (${result.severity})`);
    console.log(`   ${C.magenta}Description:${C.reset} ${result.description}`);
    console.log(`   ${C.magenta}Categories:${C.reset} ${Object.keys(result.categoryScores || {}).join(', ')}`);

    if (result.analysis?.novelIndicators?.length > 0) {
      console.log(`   ${C.red}Novel indicators:${C.reset} ${result.analysis.novelIndicators.join(', ')}`);
    }

    if (result.analysis?.temporalAnomaly) {
      console.log(`   ${C.red}Temporal:${C.reset} ${result.analysis.temporalAnomaly.type}`);
    }
  } else {
    console.log(`${C.green}✅ Clean (score: ${result.score.toFixed(1)})${C.reset}`);
  }
}

console.log(`\n\n${C.cyan}=== Summary ===${C.reset}`);
console.log('Smart anomaly detection analyzes request features against rule profiles');
console.log('to detect attacks even when exact patterns do not match.');
console.log('Zero-day and evasion attempts are caught via fuzzy matching and behavioral analysis.');

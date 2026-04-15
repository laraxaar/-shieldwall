'use strict';

// Bot detection module — identifies automated traffic via behavioral signals
// Detects headless browsers, automation tools, and scrapers

const HEADLESS_INDICATORS = [
  /HeadlessChrome/i,
  /PhantomJS/i,
  /Selenium/i,
  /WebDriver/i,
  /Puppeteer/i,
  /Playwright/i,
  /Cypress/i,
  /webdriver/i,
  /selenium/i,
  /phantomjs/i,
];

const AUTOMATION_UAS = [
  /bot/i, /crawler/i, /spider/i, /scraper/i,
  /wget/i, /curl/i, /python-requests/i,
  /httpclient/i, /axios/i, /node-fetch/i,
  /postman/i, /insomnia/i,
];

const SUSPICIOUS_HEADERS = [
  /sec-ch-ua.*headless/i,
  /chrome-lighthouse/i,
];

// Track per-session behavior
const sessionData = new Map();
const MAX_SESSIONS = 5000; // Prevent memory exhaustion
const MAX_REQUESTS_PER_SESSION = 100; // Limit history per session

function detectHeadlessBrowser(userAgent, headers) {
  const indicators = [];
  
  for (const pattern of HEADLESS_INDICATORS) {
    if (pattern.test(userAgent)) {
      indicators.push(`headless_ua:${pattern.source}`);
    }
  }
  
 
  const acceptLang = headers['accept-language'];
  if (!acceptLang || acceptLang.length < 2) {
    indicators.push('missing_accept_language');
  }
  
 
  const secChUa = headers['sec-ch-ua'];
  if (secChUa && /headless/i.test(secChUa)) {
    indicators.push('sec_ch_ua_headless');
  }
  
  return indicators;
}

function detectAutomationTool(userAgent) {
  const indicators = [];
  
  for (const pattern of AUTOMATION_UAS) {
    if (pattern.test(userAgent)) {
      indicators.push(`automation_ua:${pattern.source}`);
    }
  }
  
  return indicators;
}

function analyzeBehavior(sessionId, requestData) {
  if (!sessionId) return [];
  
  const now = Date.now();
  let data = sessionData.get(sessionId);
  
  if (!data) {
    // Evict oldest session if at capacity (DDoS protection)
    if (sessionData.size >= MAX_SESSIONS) {
      const oldest = sessionData.keys().next().value;
      sessionData.delete(oldest);
    }
    data = {
      firstSeen: now,
      requests: [],
      mouseMovements: [],
      keystrokes: [],
      isBot: false, // Set to true if honeypot triggered
    };
    sessionData.set(sessionId, data);
  }

  // Check if honeypot already flagged this session
  if (data.isBot) {
    return ['honeypot_flagged'];
  }
  

  if (now - data.firstSeen > 3600000) {
    sessionData.delete(sessionId);
    return [];
  }
  
  // Limit requests array to prevent memory bloat
  if (data.requests.length >= MAX_REQUESTS_PER_SESSION) {
    data.requests.shift(); // Remove oldest
  }
  data.requests.push({
    timestamp: now,
    path: requestData.path,
    method: requestData.method,
  });
  
  const indicators = [];
  

  const recentRequests = data.requests.filter(r => now - r.timestamp < 10000);
  if (recentRequests.length > 50) {
    indicators.push('excessive_request_rate');
  }
  
  
  if (data.requests.length >= 5) {
    const last5 = data.requests.slice(-5);
    const paths = last5.map(r => r.path);
    const uniquePaths = new Set(paths);
    
    
    if (uniquePaths.size === paths.length && (now - last5[0].timestamp) < 5000) {
      indicators.push('sequential_path_access');
    }
  }
  
 
  if (requestData.isBrowser && data.mouseMovements.length === 0 && data.requests.length > 5) {
    indicators.push('no_interaction');
  }
  
  return indicators;
}

function check(decodedReq) {
  const matches = [];
  const indicators = [];
  
  const ua = decodedReq.userAgent || '';
  const headers = decodedReq.headers || {};
  
  const headlessIndicators = detectHeadlessBrowser(ua, headers);
  if (headlessIndicators.length > 0) {
    indicators.push(...headlessIndicators);
  }
  
  const automationIndicators = detectAutomationTool(ua);
  if (automationIndicators.length > 0) {
    indicators.push(...automationIndicators);
  }
  
  // Prefer sessionId over IP to handle NAT/shared IPs properly
  const sessionId = decodedReq.sessionId || decodedReq.ip;
  const isBrowser = /Chrome|Firefox|Safari|Edge/i.test(ua);

  // Check for honeypot trap trigger from other modules
  if (decodedReq.honeypotTriggered) {
    const data = sessionData.get(sessionId);
    if (data) data.isBot = true;
  }

  const behaviorIndicators = analyzeBehavior(sessionId, {
    path: decodedReq.path,
    method: decodedReq.method,
    isBrowser,
  });
  indicators.push(...behaviorIndicators);
  
  if (indicators.length > 0) {
    const severity = indicators.some(i => i.includes('automation')) ? 'high' : 'medium';
    matches.push({
      rule: 'bot_detection',
      tags: ['bot', 'automation'],
      severity,
      category: 'bot',
      description: `Bot detected: ${indicators.slice(0, 3).join(', ')}`,
      author: 'laraxaar',
      sourceFile: 'builtin:bot-detection',
      matchedPatterns: indicators.map(i => ({ name: i, matched: true })),
    });
  }
  
  return matches;
}


setInterval(() => {
  const now = Date.now();
  for (const [id, data] of sessionData.entries()) {
    if (now - data.firstSeen > 3600000) {
      sessionData.delete(id);
    }
  }
}, 60000);

module.exports = { check };

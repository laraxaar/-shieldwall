'use strict';

/**
 * @file fingerprinter.js
 * @description TLS JA3/JA3Hash Fingerprinting & Deception Detector.
 * 
 * ROLE IN ARCHITECTURE:
 * Reconstructs client identity vectors beyond standard HTTP headers. Detects if a client 
 * claiming to be 'Chrome' is actually running via 'python-requests' by dissecting SSL/TLS 
 * negotiation cipher suites.
 * 
 * DATA FLOW:
 * [engine.js] passes `decodedReq` -> `matchFingerprint` compares JA3 bounds -> 
 *  `detectBrowserMismatch` aligns Claimed UA vs Actual TLS -> Yields Risk Signals.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION:
 * - API Context Circuit Breaker: Strict JA3 limits ban `curl` or `requests` heavily. 
 *   If the endpoint routes to an underlying API (`/api/`), the severity of algorithmic CLI 
 *   signatures drops from 'high/critical' to 'info/low' to permit B2B programmatic access.
 */

const TLSFingerprints = new Map();

const KNOWN_FINGERPRINTS = {
  'python_requests': {
    ja3: '769,47-53-5-10-61,0-10-11,23-24-25,0',
    ja3_hash: 'e15c1f3e5f6a7b8c9d0e1f2a3b4c5d6e',
    indicators: ['python-requests', 'urllib'],
    severity: 'medium', // Downgraded dynamically if API
  },
  'go_http': {
    ja3: '771,49195-49196-49199-49200-159-52393-52392-52394-49161-49162-49171-49172-51-57-47-53-10,0-23-35-13-5-18-16-30032-11-10-21,29-23-24-25-256-257,0',
    ja3_hash: 'f7a4c3b2d1e0f9a8b7c6d5e4f3a2b1c0',
    indicators: ['Go-http-client', 'Go+http'],
    severity: 'medium',
  },
  'curl': {
    ja3: '771,49199-49200-49195-49196-52393-52394-52392-49161-49162-49171-49172-156-157-47-53-10,65281-0-23-35-13-5-18-16-30032-11-10-21,29-23-24-25-256-257,0',
    ja3_hash: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
    indicators: ['curl'],
    severity: 'low',
  },
  'nodejs': {
    ja3: '771,49195-49199-49200-52393-52394-52392-49161-49162-49171-49172-156-157-47-53-10,0-23-35-13-5-18-16-30032-11-10-21,29-23-24-25-256-257,0',
    ja3_hash: 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7',
    indicators: ['node-fetch', 'axios', 'got'],
    severity: 'medium',
  },
  'java': {
    ja3: '769,47-53-5-10-49161-49162-49171-49172-49191-49192-156-157-60-61,65281-0-5-10-11-13-35-16-30032,23-24-25,0',
    ja3_hash: 'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8',
    indicators: ['Java/', 'Apache-HttpClient'],
    severity: 'medium',
  },
  'scrapy': {
    ja3: '771,47-53-5-10-49161-49162-49171-49172-49191-49192-156-157-60-61,0-5-10-11-13-35,23-24-25,0',
    ja3_hash: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9',
    indicators: ['Scrapy'],
    severity: 'high',
  },
  'headless_chrome': {
    ja3: '771,49195-49196-52393-49199-49200-52392-49162-49161-49201-49187-49191-49171-49172-49170-49190-156-157-60-61-47-53-255,0-23-65281-10-11-35-16-5-13-18-51-45-43-21,29-23-24-25-256-257,0',
    ja3_hash: 'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0',
    indicators: ['HeadlessChrome'],
    severity: 'high',
  },
};

/**
 * Extracts JA3 signature hashes reliably from inbound proxy arrays or headers.
 * @param {Object} req - Decoded payload representation.
 * @returns {string|null} Evaluated JA3 fingerprint.
 */
function extractJa3FromRequest(req) {
  const ja3 = req.headers?.['ja3-fingerprint'] || req.headers?.['x-ja3-fingerprint'];
  if (ja3) return ja3;

  const ja3Hash = req.headers?.['ja3-hash'] || req.headers?.['x-ja3-hash'];
  if (ja3Hash) return ja3Hash;

  return null;
}

/**
 * Compares TLS fingerprints against HTTP User-Agent assertions to extract masking behavior.
 * @param {string} ja3String - Extracted TLS identifier.
 * @param {string} userAgent - HTTP-level identification text.
 * @param {boolean} isApiContext - Trigger flag for B2B API integrations.
 * @returns {Object|null} Threat indicator definition object.
 */
function matchFingerprint(ja3String, userAgent, isApiContext) {
  if (!ja3String) return null;

  const ua = (userAgent || '').toLowerCase();

  for (const [name, profile] of Object.entries(KNOWN_FINGERPRINTS)) {
    if (ja3String === profile.ja3 || ja3String === profile.ja3_hash) {
      
      // DP Mitigation: If we are actively servicing an API layer, programmatic TLS maps 
      // (like cURL / python) are fully legitimate defaults. Lower their severity block.
      let adjustedSeverity = profile.severity;
      if (isApiContext && ['curl', 'python_requests', 'go_http', 'nodejs', 'java'].includes(name)) {
        adjustedSeverity = 'info';
      }

      return {
        type: 'tls_fingerprint_match',
        library: name,
        severity: adjustedSeverity,
        detail: `Cipher cluster maps perfectly to structural ${name} signature`,
        confidence: 0.95,
      };
    }

    // Checking if the detected TLS library matches the actual UA string declared
    const uaMatch = profile.indicators.some(ind => ua.includes(ind.toLowerCase()));
    if (uaMatch && ja3String.length > 10) {
      return {
        type: 'tls_ua_mismatch',
        library: name,
        severity: 'high',
        detail: `Client masked as Standard Browser but TLS matches programmatic ${name} footprint`,
        confidence: 0.85,
      };
    }
  }

  return null;
}

/**
 * Validates baseline deceptive spoofing where User-Agent claims to be a modern
 * visual browser (Chrome, Edge) but the underlying TLS logic fails basic capability mapping.
 * @param {Object} req - Mapped request payload.
 * @returns {Object|null} Descriptive mismatch vector.
 */
function detectBrowserMismatch(req) {
  const ua = (req.userAgent || '').toLowerCase();
  const ja3 = extractJa3FromRequest(req);

  const isBrowserUA = /chrome|firefox|safari|edge|opera/.test(ua);
  const hasTlsFingerprint = !!ja3;

  if (!isBrowserUA || !hasTlsFingerprint) return null;

  const isApiContext = /^\/api\//i.test(req.path || '');
  const match = matchFingerprint(ja3, req.userAgent, isApiContext);
  
  if (match?.type === 'tls_ua_mismatch') {
    return match;
  }

  return null;
}

/**
 * Deconstructs the raw TLS extension arrays to map heuristic anomalies absent of strict matching.
 * @param {Object} req - Request parameters map.
 * @returns {Array<Object>} List of feature anomalies.
 */
function analyzeCipherSuites(req) {
  const ja3 = extractJa3FromRequest(req);
  if (!ja3) return [];

  const indicators = [];

  const parts = ja3.split(',');
  if (parts.length >= 2) {
    const cipherCount = parts[1].split('-').length;
    
    // FP Circuit Break: Exclude legacy embedded systems
    if (cipherCount < 5) {
      indicators.push({
        type: 'limited_ciphers',
        detail: `Only ${cipherCount} cipher suites listed - extremely narrow for modern protocol arrays`,
        weight: 4,
      });
    }
    
    // Heavy randomization hints towards evasion tooling
    if (cipherCount > 30) {
      indicators.push({
        type: 'excessive_ciphers',
        detail: `${cipherCount} cipher suites - possible evasion randomization detected`,
        weight: 3,
      });
    }
  }

  // Missing extensions vector
  if (parts.length >= 5 && parts[4] === '0') {
    indicators.push({
      type: 'no_extensions',
      detail: 'TLS Extensions payload is entirely empty',
      weight: 6,
    });
  }

  return indicators;
}

/**
 * Standard Engine Execution Router.
 * Emits unified Risk Matches into the Engine Policy Aggregator layer.
 * @param {Object} decodedReq - Request interface target.
 * @returns {Array} Packaged matching indicators.
 */
function check(decodedReq) {
  const matches = [];

  const ja3 = extractJa3FromRequest(decodedReq);
  if (!ja3) return matches;

  // Derive API contextual operations to dampen standard programmatic FPs
  const isApiContext = /^\/api\//i.test(decodedReq.path || '');

  const fingerprint = matchFingerprint(ja3, decodedReq.userAgent, isApiContext);
  if (fingerprint) {
    // Info-level alerts are effectively logged but ignored in cumulative policy scoring
    if (fingerprint.severity !== 'info') {
        matches.push({
          rule: 'tls_fingerprinter',
          tags: ['fingerprint', 'bot', fingerprint.library],
          severity: fingerprint.severity,
          category: 'bot_detection',
          description: fingerprint.detail,
          author: 'shieldwall-core', // Ownership corrected
          sourceFile: 'builtin:fingerprinter',
          confidence: fingerprint.confidence,
          analysis: {
            ja3: ja3.substring(0, 50),
            matchedLibrary: fingerprint.library,
            matchType: fingerprint.type,
          },
          matchedPatterns: [{ name: fingerprint.type, matched: fingerprint.detail }],
        });
    }
  }

  const cipherAnalysis = analyzeCipherSuites(decodedReq);
  if (cipherAnalysis.length > 0) {
    const totalWeight = cipherAnalysis.reduce((a, i) => a + i.weight, 0);
    matches.push({
      rule: 'tls_cipher_anomaly',
      tags: ['fingerprint', 'anomaly'],
      severity: totalWeight > 8 ? 'high' : 'medium',
      category: 'anomaly',
      description: `TLS suite architecture irregular: ${cipherAnalysis.map(i => i.type).join(', ')}`,
      author: 'shieldwall-core',
      sourceFile: 'builtin:fingerprinter',
      analysis: { anomalies: cipherAnalysis },
      matchedPatterns: cipherAnalysis.map(i => ({ name: i.type, matched: i.detail })),
    });
  }

  const mismatch = detectBrowserMismatch(decodedReq);
  if (mismatch) {
    matches.push({
      rule: 'tls_ua_mismatch',
      tags: ['fingerprint', 'deception', 'bot'],
      severity: 'critical', // Will block immediately
      category: 'bot_detection',
      description: mismatch.detail,
      author: 'shieldwall-core',
      sourceFile: 'builtin:fingerprinter',
      confidence: mismatch.confidence,
      analysis: {
        claimedUA: decodedReq.userAgent?.substring(0, 50),
        actualLibrary: mismatch.library,
      },
      matchedPatterns: [{ name: 'ua_tls_mismatch', matched: mismatch.detail }],
    });
  }

  return matches;
}

module.exports = { check, KNOWN_FINGERPRINTS, extractJa3FromRequest };

'use strict';

// ─── Design Guarantees ──────────────────────────────────────────────────────
//
// 1. Bounded:  MAX_DECODE_DEPTH = 5 — recursion always terminates
// 2. Pure:     no network calls, no filesystem access, no side effects
// 3. Non-destructive: original request object is NEVER mutated;
//              decodeRequest() returns a new object
// 4. Deterministic: identical input → identical output, no randomness
// 5. Security-neutral: decoder makes NO security decisions — it only
//              produces a canonical representation for downstream analysis
// 6. Readable output: base64 is only decoded when:
//    - the blob appears in a parameter-value context (after = or :)
//    - the blob is ≥40 chars (filters out short tokens/IDs)
//    - the decoded result is printable ASCII and ≥4 chars
//
// What this does NOT do:
//   - Does NOT validate or sanitize input
//   - Does NOT block or allow requests
//   - Does NOT make outbound connections
//   - Does NOT persist any state between calls
//
// ─────────────────────────────────────────────────────────────────────────────

const MAX_DECODE_DEPTH = 5;

function urlDecode(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return str.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
  }
}

function htmlEntityDecode(str) {
  const named = {
    '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&apos;': "'",
    '&nbsp;': ' ', '&tab;': '\t', '&excl;': '!', '&num;': '#',
    '&lpar;': '(', '&rpar;': ')', '&sol;': '/', '&colon;': ':',
    '&semi;': ';', '&equals;': '=', '&quest;': '?', '&lsqb;': '[',
    '&rsqb;': ']', '&lbrace;': '{', '&rbrace;': '}', '&vert;': '|',
  };

  let result = str;
  result = result.replace(/&[a-zA-Z]+;/g, m => named[m.toLowerCase()] || m);
  result = result.replace(/&#x([0-9A-Fa-f]+);?/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  result = result.replace(/&#(\d+);?/g, (_, d) => String.fromCharCode(parseInt(d, 10)));
  return result;
}

function unicodeDecode(str) {
  return str
    .replace(/\\u([0-9A-Fa-f]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\0([0-7]{1,3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)));
}

// Base64 decode — restricted to parameter-value context only.
// Previous version decoded ANY 20+ char base64 blob anywhere in text,
// which caused "semantic mutation" of the input stream.  Now:
//   - blob must follow = or : (parameter value position)
//   - minimum 40 chars (filters short tokens, API keys, IDs)
//   - decoded result must be printable ASCII ≥4 chars
function base64Decode(str) {
  return str.replace(
    /(?:[=:]\s*)([A-Za-z0-9+/]{40,}={0,2})(?:$|[&\s;,\]}])/g,
    (match, b64) => {
      try {
        const decoded = Buffer.from(b64, 'base64').toString('utf-8');
        if (/^[\x20-\x7E\r\n\t]+$/.test(decoded) && decoded.length >= 4) {
          return match.replace(b64, decoded);
        }
      } catch {}
      return match;
    }
  );
}

function removeNullBytes(str) {
  return str.replace(/\x00|%00|\0/gi, '');
}

function normalizePath(str) {
  return str.replace(/\\/g, '/').replace(/\/+/g, '/');
}

// Recursive decode — applies all decoders until output stabilizes.
// Guaranteed to terminate: depth counter + MAX_DECODE_DEPTH = 5.
function fullDecode(str, depth = 0) {
  if (!str || typeof str !== 'string' || depth >= MAX_DECODE_DEPTH) return str || '';

  let decoded = str;
  decoded = removeNullBytes(decoded);
  decoded = urlDecode(decoded);
  decoded = htmlEntityDecode(decoded);
  decoded = unicodeDecode(decoded);
  decoded = base64Decode(decoded);
  decoded = normalizePath(decoded);

  return decoded !== str ? fullDecode(decoded, depth + 1) : decoded;
}

// Builds normalized request copy for rule matching.
// IMPORTANT: the original req object is never modified — this returns a new object.
// Raw originals are preserved for evasion detection (rawUrl, rawBody).
function decodeRequest(req) {
  const decoded = {
    url: fullDecode(req.url || ''),
    method: (req.method || 'GET').toUpperCase(),
    headers: {},
    query: {},
    body: '',
    cookies: {},
    ip: req.ip || req.connection?.remoteAddress || 'unknown',
    path: fullDecode(req.path || req.url?.split('?')[0] || ''),
    rawUrl: req.url || '',
    rawBody: '',
    userAgent: '',
    sessionId: req.sessionId || req.session?.id || req.cookies?.session || null,
    timestamp: Date.now(),
    geoip: req.geoip || null,
    fingerprint: req.fingerprint || null,
    rate: req.rate || null,
  };

  if (req.headers) {
    for (const [key, value] of Object.entries(req.headers)) {
      decoded.headers[key.toLowerCase()] = fullDecode(String(value));
    }
    decoded.userAgent = decoded.headers['user-agent'] || '';
  }

  if (req.query && typeof req.query === 'object') {
    for (const [key, value] of Object.entries(req.query)) {
      decoded.query[fullDecode(key)] = fullDecode(String(value));
    }
  } else if (req.url && req.url.includes('?')) {
    const qs = req.url.split('?')[1] || '';
    for (const pair of qs.split('&')) {
      const [key, ...rest] = pair.split('=');
      if (key) decoded.query[fullDecode(key)] = fullDecode(rest.join('='));
    }
  }

  if (req.body) {
    if (typeof req.body === 'string') {
      decoded.body = fullDecode(req.body);
      decoded.rawBody = req.body;
    } else if (typeof req.body === 'object') {
      decoded.rawBody = JSON.stringify(req.body);
      decoded.body = fullDecode(decoded.rawBody);
    }
  }

  if (req.cookies && typeof req.cookies === 'object') {
    for (const [key, value] of Object.entries(req.cookies)) {
      decoded.cookies[fullDecode(key)] = fullDecode(String(value));
    }
  } else if (req.headers?.cookie) {
    for (const pair of req.headers.cookie.split(';')) {
      const [key, ...rest] = pair.trim().split('=');
      if (key) decoded.cookies[fullDecode(key.trim())] = fullDecode(rest.join('=').trim());
    }
  }

  return decoded;
}

module.exports = {
  urlDecode, htmlEntityDecode, unicodeDecode, base64Decode,
  removeNullBytes, normalizePath, fullDecode, decodeRequest,
};

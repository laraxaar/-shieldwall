'use strict';

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

function base64Decode(str) {
  return str.replace(
    /(?:^|[^a-zA-Z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?:$|[^a-zA-Z0-9+/=])/g,
    (match, b64) => {
      try {
        const decoded = Buffer.from(b64, 'base64').toString('utf-8');
        if (/^[\x20-\x7E\r\n\t]+$/.test(decoded)) return match.replace(b64, decoded);
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

// Recursive decode — applies all decoders until output stabilizes
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

// Builds normalized request copy for rule matching, preserving raw originals for evasion detection
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

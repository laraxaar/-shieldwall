'use strict';

// Heuristic anomaly scoring — assigns suspicion score based on behavioral signals
// instead of matching specific attack signatures.  Works across injection targets
// (SQL, NoSQL, LDAP, shell, etc.) because it measures structural anomalies rather
// than matching database-specific syntax.

// ─── Threshold Calibration ──────────────────────────────────────────────────
//
//  Payload type                   | Typical score | Expected level
//  -------------------------------|---------------|---------------
//  Normal GET /api/users          |  0 – 3        | none
//  GraphQL introspection query    |  4 – 8        | none/low
//  JWT in Authorization header    |  2 – 5        | none
//  SQLi: ' OR 1=1 --             | 12 – 18       | medium/high
//  SQLi: UNION SELECT (encoded)   | 22 – 35       | high/critical
//  XSS: <script>alert(1)</script> | 14 – 20       | high
//  Multi-layer encoded payload    | 20 – 40+      | critical
//  PE/ELF binary upload (b64)     | 18 – 28       | high/critical
//
// SCORE_THRESHOLD (15):
//   Lowest score at which a known attack payload reliably triggers.
//   Below this — noise from legitimate edge cases (encoded URLs, long
//   query strings, API tokens).
//
// CRITICAL_THRESHOLD (30):
//   Score at which ≥3 independent high-weight signals fire simultaneously.
//   Extremely unlikely for legitimate traffic.
//
// Entropy 5.5:
//   English text ≈ 3.5–4.5, URL-encoded payloads ≈ 4.5–5.2,
//   base64/encrypted ≈ 5.8–6.0.  5.5 sits above normal encoded URLs
//   but below pure random / encrypted data.
//
// Special char ratio 0.30:
//   Normal URLs ≈ 5–15%, query-heavy ≈ 15–25%,
//   injection payloads ≈ 30–60%.
//
// ─────────────────────────────────────────────────────────────────────────────

const SCORE_THRESHOLD = 15;
const CRITICAL_THRESHOLD = 30;

const WEIGHTS = {
  encodingLayers: 4,
  unusualCharDensity: 3,
  longParameter: 2,
  nestedParentheses: 3,
  controlCharacters: 5,
  mixedEncoding: 4,
  reservedKeywords: 2,
  stringTerminators: 3,
  commentSyntax: 3,
  abnormalMethod: 5,
  emptyUserAgent: 2,
  pathDepth: 2,
  repeatingPatterns: 3,
  highEntropy: 4,
  parameterPollution: 5,
  rawByteInjection: 6,
  payloadInflation: 3,
  nakedRequest: 3,
  headerIntegrity: 2,
  emptyBody: 2,
  paddingEvasion: 4,
  fragmentedWords: 5,
  executablePayload: 6,
};

// ─── Signal Groups ──────────────────────────────────────────────────────────
// Grouping prevents unrelated low-confidence signals from stacking into a
// false conviction.  The final score is still a sum, but group breakdown
// lets downstream consumers (smart-anomaly, dashboard) reason about attack
// type rather than a single opaque number.

const SIGNAL_GROUPS = {
  multi_layer_encoding: 'encoding',
  mixed_encoding:       'encoding',
  high_entropy:         'encoding',

  unusual_chars:        'structural',
  control_chars:        'structural',
  deep_nesting:         'structural',
  string_terminators:   'structural',
  comment_syntax:       'structural',
  padding_evasion:      'structural',
  fragmented_words:     'structural',
  executable_payload:   'structural',
  repeating_patterns:   'structural',
  raw_bytes:            'structural',
  oversized_param:      'structural',

  abnormal_method:      'behavioral',
  no_user_agent:        'behavioral',
  deep_path:            'behavioral',
  parameter_pollution:  'behavioral',
  payload_inflation:    'behavioral',
  naked_request:        'behavioral',
  header_integrity:     'behavioral',
  empty_json_body:      'behavioral',
  keywords:             'behavioral',
};

// ─── Safe Patterns (false-positive suppression) ─────────────────────────────
// Known-safe payloads that would otherwise trigger high_entropy, keywords, or
// deep_path.  Each entry names the signal(s) to suppress when the pattern
// matches.  smart-anomaly still analyzes the full request — this only quiets
// the fast-path heuristic scorer.

const SAFE_PATTERNS = [
  // JWT tokens: high entropy is expected
  { test: (v) => /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v), suppress: ['high_entropy'] },
  // GraphQL introspection: uses keywords like "select"-ish field names
  { test: (v) => /\b__schema\b|\bintrospection\b|\b__type\b/i.test(v), suppress: ['keywords'] },
  // Short base64 blobs (API keys, tokens) — high entropy is normal
  { test: (v) => /^[A-Za-z0-9+/]{40,}={0,2}$/.test(v), suppress: ['high_entropy'], condition: (v) => v.length < 500 },
  // Hex hashes (SHA-256, MD5, etc.)
  { test: (v) => /^[a-f0-9]{32,64}$/i.test(v), suppress: ['high_entropy'] },
  // Versioned REST APIs often have deep paths
  { test: (v) => /^\/api\/v\d+\//i.test(v), suppress: ['deep_path'] },
];

function detectSafePatterns(allValues, query) {
  const suppressed = new Set();
  const candidates = [allValues, ...Object.values(query || {}).map(String)];
  for (const val of candidates) {
    if (!val) continue;
    for (const sp of SAFE_PATTERNS) {
      if (sp.test(val) && (!sp.condition || sp.condition(val))) {
        for (const s of sp.suppress) suppressed.add(s);
      }
    }
  }
  return suppressed;
}

// ─── Utility Functions ──────────────────────────────────────────────────────

// Secondary guard for regex-heavy functions — prevents pathological input
// from burning CPU even after the primary MAX_ANALYSIS_SIZE slice.
const MAX_REGEX_INPUT = 5000;

function charClassRatio(str, regex) {
  if (!str || !str.length) return 0;
  const m = str.match(regex);
  return m ? m.length / str.length : 0;
}

function detectMixedEncoding(str) {
  if (!str) return 0;
  let n = 0;
  if (/%[0-9A-Fa-f]{2}/.test(str)) n++;
  if (/&#(x[0-9A-Fa-f]+|\d+);?/.test(str)) n++;
  if (/\\u[0-9A-Fa-f]{4}/.test(str)) n++;
  if (/\\x[0-9A-Fa-f]{2}/.test(str)) n++;
  if (/[A-Za-z0-9+/]{20,}={0,2}/.test(str)) n++;
  return n;
}

function countEncodingLayers(str) {
  if (!str) return 0;
  let layers = 0, current = str;
  for (let i = 0; i < 5; i++) {
    try {
      const d = decodeURIComponent(current);
      if (d === current) break;
      current = d; layers++;
    } catch { break; }
  }
  return layers;
}

function nestingDepth(str) {
  if (!str) return 0;
  let max = 0, depth = 0;
  for (const ch of str) {
    if ('([{'.includes(ch)) { depth++; if (depth > max) max = depth; }
    else if (')]}'.includes(ch)) depth = Math.max(0, depth - 1);
  }
  return max;
}

function repeatingRatio(str) {
  if (!str || str.length < 8) return 0;
  // Cap input to prevent regex backtracking on huge payloads
  const capped = str.length > MAX_REGEX_INPUT ? str.slice(0, MAX_REGEX_INPUT) : str;
  const runs = capped.match(/(.)\1{4,}|(\.\.\/){3,}|(\.\.\\){3,}/g);
  if (!runs) return 0;
  return runs.reduce((a, r) => a + r.length, 0) / capped.length;
}

const SOFT_KEYWORDS = /\b(select|union|insert|update|delete|drop|alter|exec|eval|system|passthru|shell_exec|require|include|document\.|window\.)\b/gi;

// Shannon entropy — high entropy indicates encrypted/encoded attack payloads.
// English text ≈ 3.5–4.5 bits, base64 ≈ 5.8–6.0 bits.
function calculateEntropy(str) {
  if (!str || str.length < 10) return 0;
  const freq = new Map();
  for (const char of str) {
    freq.set(char, (freq.get(char) || 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Detect HTTP Parameter Pollution (duplicate keys)
function detectParameterPollution(decodedReq) {
  const indicators = [];
  const query = decodedReq.query || {};
  const body = decodedReq.body || {};

  for (const [key, val] of Object.entries(query)) {
    if (Array.isArray(val)) {
      indicators.push(`query:${key}(${val.length}x)`);
    }
  }

  if (typeof body === 'object' && body !== null) {
    for (const [key, val] of Object.entries(body)) {
      if (Array.isArray(val)) {
        indicators.push(`body:${key}(${val.length}x)`);
      }
    }
  }

  // Safer regex: replaced .* with non-greedy bounded pattern to prevent
  // catastrophic backtracking on long query strings
  const rawUrl = decodedReq.rawUrl || '';
  const dupPattern = /[?&](\w+)=[^&]*&(?:[^&]*&)*\1=/g;
  const dups = [...rawUrl.matchAll(dupPattern)];
  for (const match of dups) {
    indicators.push(`raw:${match[1]}`);
  }

  return indicators;
}

// Detect raw control bytes (ASCII < 32, excluding tab/lf/cr/space)
function detectRawBytes(str) {
  if (!str) return [];
  const found = [];
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if ((code >= 0 && code <= 8) || (code >= 14 && code <= 31) || code === 127) {
      found.push(`0x${code.toString(16).padStart(2, '0')}@pos${i}`);
    }
  }
  return found;
}

// Detect payload inflation (large value for few keys)
function detectPayloadInflation(decodedReq) {
  const body = decodedReq.body;
  if (!body || typeof body !== 'object') return null;

  const keys = Object.keys(body);
  if (keys.length === 0) return null;

  const bodyStr = JSON.stringify(body);
  const avgSize = bodyStr.length / keys.length;

  if (avgSize > 100000 && keys.length <= 3) {
    return { ratio: avgSize, keys: keys.length, total: bodyStr.length };
  }
  return null;
}

// Detect naked requests (poor headers from scripts)
function detectNakedRequest(headers, userAgent) {
  const indicators = [];

  if (!headers['accept'] && !headers['Accept']) {
    indicators.push('missing_accept');
  }

  if (!headers['accept-language'] && !headers['Accept-Language']) {
    indicators.push('missing_accept_language');
  }

  if (!headers['accept-encoding'] && !headers['Accept-Encoding']) {
    indicators.push('missing_accept_encoding');
  }

  const ua = userAgent || '';
  if (/^python-requests|^axios|^node-fetch|^http\.client|^Go-http/i.test(ua)) {
    indicators.push('automation_ua');
  }

  return indicators;
}

// Check header integrity for browser-like requests
function checkHeaderIntegrity(method, headers, userAgent) {
  const indicators = [];
  const isBrowser = /Chrome|Firefox|Safari|Edge/i.test(userAgent || '');

  if (!isBrowser) return indicators;

  if (!headers['accept'] && !headers['Accept']) {
    indicators.push('browser_no_accept');
  }

  if (!headers['accept-language'] && !headers['Accept-Language']) {
    indicators.push('browser_no_lang');
  }

  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const hasOrigin = headers['origin'] || headers['Origin'];
    const hasReferer = headers['referer'] || headers['Referer'];
    if (!hasOrigin && !hasReferer) {
      indicators.push('post_no_origin');
    }
  }

  return indicators;
}

// Check for empty body with JSON content-type
function detectEmptyBody(headers, body) {
  const contentType = headers['content-type'] || headers['Content-Type'] || '';
  if (contentType.includes('application/json')) {
    if (!body || (typeof body === 'string' && body.trim().length === 0) ||
        (typeof body === 'object' && Object.keys(body).length === 0)) {
      return true;
    }
  }
  return false;
}

// Detect padding evasion (e.g. SELECT       *       FROM)
function detectPaddingEvasion(str) {
  if (!str) return false;
  const capped = str.length > MAX_REGEX_INPUT ? str.slice(0, MAX_REGEX_INPUT) : str;
  return /\b(select|union|from|where|insert|delete|update|drop)\s{5,}/i.test(capped);
}

// Detect fragmented keywords (e.g. 's'+'e'+'l'+'e' or concat('u','n','i'))
function detectFragmentedWords(str) {
  if (!str) return false;
  const capped = str.length > MAX_REGEX_INPUT ? str.slice(0, MAX_REGEX_INPUT) : str;
  const concatSyntax = /(['"]\w['"]\s*(\+|\|\|)\s*){3,}/i;
  const sqlConcat = /concat\(\s*['"]\w['"]\s*(,\s*['"]\w['"]\s*){3,}\)/i;
  const inlineChr = /(chr|char)\(\d{2,3}\)\s*(\|\||\+)\s*(chr|char)\(/i;
  return concatSyntax.test(capped) || sqlConcat.test(capped) || inlineChr.test(capped);
}

// Detect Base64 encoded executable headers (Windows PE MZ, Linux ELF)
function detectExecutablePayload(str) {
  if (!str) return false;
  return /(TVqQ(A|I|w|Q)[A-Za-z0-9+/=]{10,}|f0VMR[A-Za-z0-9+/=]{10,})/.test(str);
}

// ─── Main Analyzer ──────────────────────────────────────────────────────────

function analyze(decodedReq) {
  const factors = [];
  let score = 0;
  const groupScores = { encoding: 0, structural: 0, behavioral: 0 };

  const add = (weight, name, detail) => {
    score += weight;
    const group = SIGNAL_GROUPS[name] || 'structural';
    groupScores[group] = (groupScores[group] || 0) + weight;
    factors.push({ weight, name, detail, group });
  };

  const MAX_ANALYSIS_SIZE = 10000;
  const allValues = [
    decodedReq.url?.slice(0, MAX_ANALYSIS_SIZE),
    decodedReq.body?.slice(0, MAX_ANALYSIS_SIZE),
    ...Object.values(decodedReq.query || {}).map(v => String(v).slice(0, 500)),
    ...Object.values(decodedReq.cookies || {}).map(v => String(v).slice(0, 500)),
  ].join('\n').slice(0, MAX_ANALYSIS_SIZE);

  // Detect safe patterns to suppress false-positive-prone signals
  const suppressed = detectSafePatterns(allValues, decodedReq.query);

  const encLayers = countEncodingLayers(decodedReq.rawUrl || '');
  if (encLayers >= 2) add(WEIGHTS.encodingLayers * encLayers, 'multi_layer_encoding', `${encLayers} encoding layers detected`);

  const mixedEnc = detectMixedEncoding(allValues);
  if (mixedEnc >= 2) add(WEIGHTS.mixedEncoding * (mixedEnc - 1), 'mixed_encoding', `${mixedEnc} different encoding schemes in one request`);

  const specialRatio = charClassRatio(allValues, /[^a-zA-Z0-9\s.,\-_@]/g);
  if (specialRatio > 0.30) add(WEIGHTS.unusualCharDensity * Math.ceil(specialRatio * 10), 'unusual_chars', `${(specialRatio * 100).toFixed(0)}% special characters`);

  const ctrlChars = (allValues.match(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g) || []).length;
  if (ctrlChars > 0) add(WEIGHTS.controlCharacters, 'control_chars', `${ctrlChars} control characters found`);

  const depth = nestingDepth(allValues);
  if (depth >= 3) add(WEIGHTS.nestedParentheses, 'deep_nesting', `Nesting depth ${depth}`);

  for (const val of Object.values(decodedReq.query || {})) {
    if (val && val.length > 500) { add(WEIGHTS.longParameter, 'oversized_param', `${val.length} char parameter`); break; }
  }

  if (detectPaddingEvasion(allValues)) add(WEIGHTS.paddingEvasion, 'padding_evasion', 'Suspicious whitespace padding evasion');
  if (detectFragmentedWords(allValues)) add(WEIGHTS.fragmentedWords, 'fragmented_words', 'String concatenation / character evasion');
  if (detectExecutablePayload(allValues)) add(WEIGHTS.executablePayload, 'executable_payload', 'Base64 executable header (PE/ELF) detected');

  const repRatio = repeatingRatio(allValues);
  if (repRatio > 0.15) add(WEIGHTS.repeatingPatterns, 'repeating_patterns', `${(repRatio * 100).toFixed(0)}% repetitive content`);

  if (!suppressed.has('string_terminators')) {
    const terminators = (allValues.match(/['"`]/g) || []).length;
    if (terminators >= 4) add(WEIGHTS.stringTerminators, 'string_terminators', `${terminators} quote characters`);
  }

  const comments = (allValues.match(/(--|\/\*|#|\/\/)/g) || []).length;
  if (comments >= 2) add(WEIGHTS.commentSyntax, 'comment_syntax', `${comments} comment tokens`);

  if (!suppressed.has('keywords')) {
    const keywords = allValues.match(SOFT_KEYWORDS) || [];
    if (keywords.length >= 3) add(WEIGHTS.reservedKeywords, 'keywords', `${keywords.length} programming keywords`);
  }

  const method = (decodedReq.method || '').toUpperCase();
  const normalMethods = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);
  if (method && !normalMethods.has(method)) add(WEIGHTS.abnormalMethod, 'abnormal_method', `Non-standard method "${method}"`);

  if (!decodedReq.userAgent || decodedReq.userAgent.length < 5) add(WEIGHTS.emptyUserAgent, 'no_user_agent', 'Missing User-Agent');

  if (!suppressed.has('deep_path')) {
    const pathSegs = (decodedReq.path || '').split('/').filter(Boolean).length;
    if (pathSegs > 10) add(WEIGHTS.pathDepth, 'deep_path', `${pathSegs} path segments`);
  }

  // Entropy check: require minimum payload length to avoid false positives
  // on short high-entropy strings (UUIDs, short tokens)
  if (!suppressed.has('high_entropy')) {
    const entropy = calculateEntropy(allValues);
    if (entropy > 5.5 && allValues.length > 50) add(WEIGHTS.highEntropy, 'high_entropy', `Entropy ${entropy.toFixed(2)} (likely encoded payload)`);
  }

  const pollution = detectParameterPollution(decodedReq);
  if (pollution.length > 0) add(WEIGHTS.parameterPollution, 'parameter_pollution', `${pollution.length} duplicate keys: ${pollution.slice(0, 3).join(', ')}`);

  const rawBytes = detectRawBytes(allValues);
  if (rawBytes.length > 0) add(WEIGHTS.rawByteInjection, 'raw_bytes', `${rawBytes.length} control bytes: ${rawBytes.slice(0, 3).join(', ')}`);

  const inflation = detectPayloadInflation(decodedReq);
  if (inflation) add(WEIGHTS.payloadInflation, 'payload_inflation', `${(inflation.ratio/1024).toFixed(1)}KB avg per ${inflation.keys} keys`);

  const naked = detectNakedRequest(decodedReq.headers, decodedReq.userAgent);
  if (naked.length > 0) add(WEIGHTS.nakedRequest, 'naked_request', naked.slice(0, 3).join(', '));

  const headerIssues = checkHeaderIntegrity(decodedReq.method, decodedReq.headers, decodedReq.userAgent);
  if (headerIssues.length > 0) add(WEIGHTS.headerIntegrity, 'header_integrity', headerIssues.join(', '));

  if (detectEmptyBody(decodedReq.headers, decodedReq.body)) {
    add(WEIGHTS.emptyBody, 'empty_json_body', 'Content-Type: application/json but body is empty');
  }

  let level = 'none';
  if (score >= CRITICAL_THRESHOLD) level = 'critical';
  else if (score >= SCORE_THRESHOLD) level = 'high';
  else if (score >= SCORE_THRESHOLD * 0.6) level = 'medium';
  else if (score >= SCORE_THRESHOLD * 0.3) level = 'low';

  return {
    score, level, threshold: SCORE_THRESHOLD, factors, groupScores,
    suppressedSignals: suppressed.size > 0 ? [...suppressed] : undefined,
    dominantGroup: Object.entries(groupScores).sort((a, b) => b[1] - a[1])[0]?.[0] || 'none',
    description: factors.length ? `Anomaly score ${score}/${CRITICAL_THRESHOLD}: ${factors.map(f => f.name).join(', ')}` : 'Clean',
  };
}

function check(decodedReq) {
  const result = analyze(decodedReq);

  if (result.score < SCORE_THRESHOLD * 0.3) {
    return [];
  }

  if (result.score < SCORE_THRESHOLD) {
    return [{
      rule: 'anomaly_detection',
      tags: ['anomaly', 'low_confidence', 'preliminary'],
      severity: 'low',
      category: 'anomaly',
      description: `Preliminary anomaly signals detected (score ${result.score}/${SCORE_THRESHOLD}). Recommend smart-anomaly analysis.`,
      author: 'laraxaar',
      sourceFile: 'builtin:anomaly',
      matchedPatterns: result.factors.map(f => ({ name: f.name, matched: f.detail })),
      analysis: { ...result, recommendation: 'escalate_to_smart_anomaly' },
      escalateTo: 'smart_anomaly',
    }];
  }

  return [{
    rule: 'anomaly_detection',
    tags: ['anomaly', result.level === 'critical' ? 'confirmed' : 'suspicious'],
    severity: result.level,
    category: 'anomaly',
    description: result.description,
    author: 'laraxaar',
    sourceFile: 'builtin:anomaly',
    matchedPatterns: result.factors.map(f => ({ name: f.name, matched: f.detail })),
    analysis: result,
  }];
}

module.exports = { analyze, check, SCORE_THRESHOLD, CRITICAL_THRESHOLD };

'use strict';

// Heuristic anomaly scoring — assigns suspicion score based on behavioral signals
// instead of matching specific attack signatures.  Database/protocol agnostic.

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
};

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
  const runs = str.match(/(.)\1{4,}|(\.\.\/?){3,}|(\.\.\\?){3,}/g);
  if (!runs) return 0;
  return runs.reduce((a, r) => a + r.length, 0) / str.length;
}

const SOFT_KEYWORDS = /\b(select|union|insert|update|delete|drop|alter|exec|eval|system|passthru|shell_exec|require|include|document\.|window\.)\b/gi;

function analyze(decodedReq) {
  const factors = [];
  let score = 0;

  const add = (weight, name, detail) => { score += weight; factors.push({ weight, name, detail }); };

  const allValues = [
    decodedReq.url, decodedReq.body,
    ...Object.values(decodedReq.query || {}),
    ...Object.values(decodedReq.cookies || {}),
  ].join('\n');

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

  const repRatio = repeatingRatio(allValues);
  if (repRatio > 0.15) add(WEIGHTS.repeatingPatterns, 'repeating_patterns', `${(repRatio * 100).toFixed(0)}% repetitive content`);

  const terminators = (allValues.match(/['"`]/g) || []).length;
  if (terminators >= 4) add(WEIGHTS.stringTerminators, 'string_terminators', `${terminators} quote characters`);

  const comments = (allValues.match(/(--|\/\*|#|\/\/)/g) || []).length;
  if (comments >= 2) add(WEIGHTS.commentSyntax, 'comment_syntax', `${comments} comment tokens`);

  const keywords = allValues.match(SOFT_KEYWORDS) || [];
  if (keywords.length >= 3) add(WEIGHTS.reservedKeywords, 'keywords', `${keywords.length} programming keywords`);

  const method = (decodedReq.method || '').toUpperCase();
  const normalMethods = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);
  if (method && !normalMethods.has(method)) add(WEIGHTS.abnormalMethod, 'abnormal_method', `Non-standard method "${method}"`);

  if (!decodedReq.userAgent || decodedReq.userAgent.length < 5) add(WEIGHTS.emptyUserAgent, 'no_user_agent', 'Missing User-Agent');

  const pathSegs = (decodedReq.path || '').split('/').filter(Boolean).length;
  if (pathSegs > 10) add(WEIGHTS.pathDepth, 'deep_path', `${pathSegs} path segments`);

  let level = 'none';
  if (score >= CRITICAL_THRESHOLD) level = 'critical';
  else if (score >= SCORE_THRESHOLD) level = 'high';
  else if (score >= SCORE_THRESHOLD * 0.6) level = 'medium';
  else if (score >= SCORE_THRESHOLD * 0.3) level = 'low';

  return { score, level, threshold: SCORE_THRESHOLD, factors,
    description: factors.length ? `Anomaly score ${score}/${CRITICAL_THRESHOLD}: ${factors.map(f => f.name).join(', ')}` : 'Clean' };
}

function check(decodedReq) {
  const result = analyze(decodedReq);
  if (result.score < SCORE_THRESHOLD) return [];
  return [{
    rule: 'anomaly_detection', tags: ['anomaly'], severity: result.level, category: 'anomaly',
    description: result.description, author: 'ShieldWall', sourceFile: 'builtin:anomaly',
    matchedPatterns: result.factors.map(f => ({ name: f.name, matched: f.detail })),
    analysis: result,
  }];
}

module.exports = { analyze, check, SCORE_THRESHOLD, CRITICAL_THRESHOLD };

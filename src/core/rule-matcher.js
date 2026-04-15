'use strict';

// Rule matcher — evaluates compiled .shield ASTs against decoded requests

const TARGET_MAP = {
  'request.url': 'url', 'request.path': 'path', 'request.body': 'body',
  'request.query': 'queryString', 'request.headers': 'headerString',
  'request.cookies': 'cookieString', 'request.method': 'method',
  'request.useragent': 'userAgent', 'request.user_agent': 'userAgent',
  'request.ip': 'ip', 'request.raw_url': 'rawUrl', 'request.raw_body': 'rawBody',
  'request.session': 'sessionId', 'request.sessionid': 'sessionId',
  'request.timestamp': 'timestamp', 'request.time': 'timestamp',
  'request.geoip': 'geoipString', 'request.geo': 'geoipString',
  'request.fingerprint': 'fingerprintString', 'request.fp': 'fingerprintString',
  'request.rate': 'rateString',
  'request.content_type': 'contentType', 'request.hostname': 'hostname',
  'request.protocol': 'protocol',
};

function prepareMatchData(d) {
  const data = {
    url: d.url || '', path: d.path || '', body: d.body || '',
    method: d.method || '', userAgent: d.userAgent || '', ip: d.ip || '',
    rawUrl: d.rawUrl || '', rawBody: d.rawBody || '',
    queryString: '', headerString: '', cookieString: '', full: '',
    sessionId: d.sessionId || '',
    timestamp: d.timestamp || Date.now(),
    geoipString: '',
    fingerprintString: '',
    rateString: '',
    contentType: (d.headers && (d.headers['content-type'] || d.headers['Content-Type'])) || '',
    hostname: (d.headers && (d.headers['host'] || d.headers['Host'])) || '',
    protocol: d.protocol || 'http',
  };
  if (d.query && typeof d.query === 'object') data.queryString = Object.entries(d.query).map(([k, v]) => `${k}=${v}`).join('&');
  if (d.headers && typeof d.headers === 'object') data.headerString = Object.entries(d.headers).map(([k, v]) => `${k}: ${v}`).join('\n');
  if (d.cookies && typeof d.cookies === 'object') data.cookieString = Object.entries(d.cookies).map(([k, v]) => `${k}=${v}`).join('; ');
  if (d.geoip && typeof d.geoip === 'object') data.geoipString = Object.entries(d.geoip).map(([k, v]) => `${k}=${v}`).join(';');
  if (d.fingerprint && typeof d.fingerprint === 'object') data.fingerprintString = Object.entries(d.fingerprint).map(([k, v]) => `${k}=${v}`).join(';');
  if (d.rate && typeof d.rate === 'object') data.rateString = Object.entries(d.rate).map(([k, v]) => `${k}=${v}`).join(';');
  data.full = [data.url, data.queryString, data.body, data.headerString, data.cookieString, data.geoipString, data.fingerprintString].join('\n');
  return data;
}

function testPattern(def, text) { return def?.compiled && text ? def.compiled.test(text) : false; }

function resolveTarget(name, rule, md) {
  if (rule.targets?.[name]) { const mapped = TARGET_MAP[rule.targets[name]] || rule.targets[name]; return md[mapped] || ''; }
  return md.full;
}

function evaluate(node, rule, md) {
  if (!node) return true;
  switch (node.type) {
    case 'and': return evaluate(node.left, rule, md) && evaluate(node.right, rule, md);
    case 'or': return evaluate(node.left, rule, md) || evaluate(node.right, rule, md);
    case 'not': return !evaluate(node.expr, rule, md);
    case 'match': return testPattern(rule.strings[node.pattern], md.full);
    case 'match_in': return testPattern(rule.strings[node.pattern], resolveTarget(node.target, rule, md));
    case 'any_of_them': return Object.values(rule.strings).some(d => testPattern(d, md.full));
    case 'all_of_them': return Object.values(rule.strings).every(d => testPattern(d, md.full));
    case 'any_of': return node.vars.some(v => testPattern(rule.strings[v], md.full));
    case 'all_of': return node.vars.every(v => testPattern(rule.strings[v], md.full));
    case 'boolean': return node.value;
    default: return false;
  }
}

function matchAllRules(rules, decodedReq) {
  const md = prepareMatchData(decodedReq);
  const matches = [];
  for (const rule of rules) {
    if (!evaluate(rule.condition, rule, md)) continue;
    const mp = [];
    for (const [name, def] of Object.entries(rule.strings)) {
      if (testPattern(def, md.full)) { const m = md.full.match(def.compiled); mp.push({ name, matched: m ? m[0] : '(matched)' }); }
    }
    matches.push({
      rule: rule.name, tags: rule.tags, severity: rule.meta.severity || 'medium',
      category: rule.tags[0] || rule.meta.category || 'unknown',
      description: rule.meta.description || '', author: rule.meta.author || 'ShieldWall',
      sourceFile: rule.sourceFile || 'inline', matchedPatterns: mp,
    });
  }
  return matches;
}

module.exports = { prepareMatchData, testPattern, evaluate, matchAllRules, TARGET_MAP };

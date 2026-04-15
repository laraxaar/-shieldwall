'use strict';

// XSS structural patterns (tags, handlers, protocol, DOM sinks)

const PATTERNS = [
  { name: 'xss_tag_exec', pattern: /<\s*(script|iframe|object|embed|applet|svg)[\s>\/]/i, severity: 'critical', description: 'Executable HTML tag' },
  { name: 'xss_event_handler', pattern: /\bon(error|load|click|mouse\w+|focus|blur|submit|key\w+)\s*=/i, severity: 'high', description: 'Event handler attribute' },
  { name: 'xss_proto_exec', pattern: /(javascript|vbscript)\s*:/i, severity: 'critical', description: 'Script protocol handler' },
  { name: 'xss_dom_sink', pattern: /document\s*\.\s*(cookie|write|location)|\.innerHTML\s*=/i, severity: 'critical', description: 'DOM property access' },
  { name: 'xss_eval_call', pattern: /\b(eval|Function)\s*\(\s*['"`\w$]/i, severity: 'high', description: 'Dynamic code execution' },
  { name: 'xss_template_inject', pattern: /\{\{.*constructor\.|__proto__/i, severity: 'high', description: 'Template injection' },
];

function check(decodedReq) {
  const haystack = [decodedReq.url, decodedReq.body, decodedReq.path, Object.values(decodedReq.query || {}).join(' '), Object.values(decodedReq.cookies || {}).join(' '), decodedReq.userAgent].join('\n');
  const matches = [];
  for (const r of PATTERNS) {
    if (r.pattern.test(haystack)) {
      const f = haystack.match(r.pattern);
      matches.push({ rule: r.name, tags: ['xss'], severity: r.severity, category: 'xss', description: r.description, author: 'ShieldWall', sourceFile: 'builtin:xss', matchedPatterns: [{ name: r.name, matched: f?.[0] || '' }] });
    }
  }
  return matches;
}

module.exports = { check, PATTERNS };

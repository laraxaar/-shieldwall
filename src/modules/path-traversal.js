'use strict';

// Path traversal / LFI / RFI patterns (encoding evasion is handled by anomaly + .shield rules)

const PATTERNS = [
  { name: 'traversal_dotdot', pattern: /\.\.[\/\\]/, severity: 'critical', description: 'Directory traversal sequence' },
  { name: 'traversal_sensitive_nix', pattern: /\/(etc\/(passwd|shadow|hosts)|proc\/(self|[0-9]+)\/(environ|cmdline))/, severity: 'critical', description: 'Sensitive Linux file access' },
  { name: 'traversal_sensitive_win', pattern: /(boot\.ini|windows[\/\\](system32|win\.ini))/i, severity: 'critical', description: 'Sensitive Windows file access' },
  { name: 'traversal_app_config', pattern: /(\.(env|git\/|htpasswd|ssh\/))/i, severity: 'high', description: 'Application config/secret access' },
  { name: 'traversal_rfi', pattern: /(include|require|file|page)=\s*https?:\/\//i, severity: 'critical', description: 'Remote file inclusion' },
  { name: 'traversal_php_wrapper', pattern: /php:\/\/(filter|input|data|expect)/i, severity: 'critical', description: 'PHP stream wrapper exploitation' },
  { name: 'traversal_null_byte', pattern: /%00\.(php|jsp|asp|html|txt)/i, severity: 'critical', description: 'Null byte path truncation' },
];

function check(decodedReq) {
  const haystack = [decodedReq.url, decodedReq.rawUrl, decodedReq.body, decodedReq.path, Object.values(decodedReq.query || {}).join(' ')].join('\n');
  const matches = [];
  for (const r of PATTERNS) {
    if (r.pattern.test(haystack)) {
      const f = haystack.match(r.pattern);
      matches.push({ rule: r.name, tags: ['traversal'], severity: r.severity, category: 'path-traversal', description: r.description, author: 'ShieldWall', sourceFile: 'builtin:path-traversal', matchedPatterns: [{ name: r.name, matched: f?.[0] || '' }] });
    }
  }
  return matches;
}

module.exports = { check, PATTERNS };

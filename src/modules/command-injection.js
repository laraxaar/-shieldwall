'use strict';

// Command injection — structural pair: shell metacharacter + command name

const PATTERNS = [
  { name: 'cmdi_chain', pattern: /[;|&]{1,2}\s*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python[23]?|perl|ruby|php)\b/i, severity: 'critical', description: 'Shell chaining attempt' },
  { name: 'cmdi_substitution', pattern: /(`[^`]{2,}`|\$\([^)]{2,}\))/, severity: 'high', description: 'Command substitution' },
  { name: 'cmdi_reverse_shell', pattern: /(bash\s+-i|\/dev\/(tcp|udp)\/|mkfifo|socat\s+.*exec)/i, severity: 'critical', description: 'Reverse shell attempt' },
  { name: 'cmdi_windows', pattern: /\b(cmd\s*\/[ck]|powershell\s+(-\w+\s+)*\w)/i, severity: 'critical', description: 'Windows shell execution' },
  { name: 'cmdi_download_exec', pattern: /(wget|curl)\s+[^\s]+\s*\|\s*(bash|sh)/i, severity: 'critical', description: 'Download-and-execute' },
];

function check(decodedReq) {
  const haystack = [decodedReq.url, decodedReq.body, decodedReq.path, Object.values(decodedReq.query || {}).join(' ')].join('\n');
  const matches = [];
  for (const r of PATTERNS) {
    if (r.pattern.test(haystack)) {
      const f = haystack.match(r.pattern);
      matches.push({ rule: r.name, tags: ['cmdi'], severity: r.severity, category: 'command-injection', description: r.description, author: 'ShieldWall', sourceFile: 'builtin:command-injection', matchedPatterns: [{ name: r.name, matched: f?.[0] || '' }] });
    }
  }
  return matches;
}

module.exports = { check, PATTERNS };

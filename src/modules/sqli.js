'use strict';

// Structural injection patterns (DB-agnostic safety net — anomaly scorer handles the rest)

const PATTERNS = [
  { name: 'injection_context_break', pattern: /['"`]\s*(or|and|union|having)\b/i, severity: 'critical', description: 'Quote followed by SQL keyword — context-breaking injection' },
  { name: 'injection_stacked', pattern: /;\s*(drop|delete|update|insert|alter|truncate|exec)\b/i, severity: 'critical', description: 'Semicolon + destructive statement — stacked query' },
  { name: 'injection_time_probe', pattern: /(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(/i, severity: 'critical', description: 'Time-delay function — blind injection probe' },
  { name: 'injection_file_ops', pattern: /(load_file|into\s+(out|dump)file)\s*\(/i, severity: 'critical', description: 'File I/O function — data exfiltration' },
  { name: 'injection_info_recon', pattern: /information_schema\.|sys\.(tables|columns)|@@version/i, severity: 'high', description: 'Database schema reconnaissance' },
  { name: 'injection_nosql', pattern: /\$(where|gt|gte|lt|lte|ne|regex)\s*:/i, severity: 'critical', description: 'NoSQL operator injection' },
  { name: 'injection_comment_trail', pattern: /['"`]\s*(--|#|\/\*)/i, severity: 'high', description: 'Quote + comment — query truncation' },
];

function testFields(pattern, decodedReq) {
  // Check each field individually - more memory efficient than joining
  const fields = [
    decodedReq.url, decodedReq.body, decodedReq.path,
    ...Object.values(decodedReq.query || {}),
    ...Object.values(decodedReq.cookies || {}),
  ];
  for (const field of fields) {
    if (field && pattern.test(String(field))) return String(field).match(pattern);
  }
  return null;
}

function check(decodedReq) {
  const matches = [];
  for (const r of PATTERNS) {
    const matched = testFields(r.pattern, decodedReq);
    if (matched) {
      matches.push({ rule: r.name, tags: ['injection'], severity: r.severity, category: 'injection', description: r.description, author: 'ShieldWall', sourceFile: 'builtin:sqli', matchedPatterns: [{ name: r.name, matched: matched[0] || '' }] });
    }
  }
  return matches;
}

module.exports = { check, PATTERNS };

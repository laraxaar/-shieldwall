'use strict';

// Honeypot traps — invisible HTML elements and fake endpoints that only bots interact with

const TRAP_PATHS = new Set([
  '/admin-panel', '/wp-admin', '/wp-login.php', '/administrator',
  '/phpmyadmin', '/api/internal/debug', '/api/v1/admin/users',
  '/backup', '/backup.sql', '/database.sql', '/db-backup.tar.gz',
  '/.env', '/.git/config', '/server-status', '/debug/vars',
  '/actuator/env', '/config.php.bak', '/xmlrpc.php', '/install.php',
]);

const HIDDEN_FIELD_NAME = '_hp_token';
const TRAP_HEADER = 'X-Trap-Token';

function generateTrapHTML(nonce) {
  return `
<div aria-hidden="true" style="position:absolute;left:-9999px;top:-9999px;height:0;width:0;overflow:hidden;pointer-events:none;opacity:0">
  <form action="/api/internal/debug" method="POST" tabindex="-1">
    <input type="text" name="username" value="" autocomplete="off" tabindex="-1">
    <input type="password" name="password" value="" autocomplete="off" tabindex="-1">
    <input type="hidden" name="${HIDDEN_FIELD_NAME}" value="${nonce}">
    <input type="email" name="email" value="" tabindex="-1">
    <button type="submit" tabindex="-1"></button>
  </form>
  <a href="/admin-panel">Admin</a>
  <a href="/api/v1/admin/users">Users API</a>
  <a href="/backup.sql">Backup</a>
  <a href="/.env">Config</a>
  <a href="/.git/config">Repository</a>
</div>`;
}

function check(decodedReq) {
  const matches = [];
  const path = (decodedReq.path || '').toLowerCase().replace(/\/+$/, '');

  if (TRAP_PATHS.has(path)) {
    matches.push({
      rule: 'honeypot_trap_path', tags: ['honeypot', 'bot'], severity: 'high', category: 'honeypot',
      description: `Bot hit trap endpoint ${path} — no legitimate user would visit this`,
      author: 'ShieldWall', sourceFile: 'builtin:honeypot',
      matchedPatterns: [{ name: 'trap_path', matched: path }],
    });
  }

  const body = decodedReq.body || '';
  const bodyObj = typeof body === 'string' ? {} : body;

  if (bodyObj[HIDDEN_FIELD_NAME] || body.includes(HIDDEN_FIELD_NAME)) {
    matches.push({
      rule: 'honeypot_hidden_field', tags: ['honeypot', 'bot'], severity: 'critical', category: 'honeypot',
      description: 'Bot submitted invisible honeypot form field',
      author: 'ShieldWall', sourceFile: 'builtin:honeypot',
      matchedPatterns: [{ name: 'hidden_field', matched: HIDDEN_FIELD_NAME }],
    });
  }

  if (decodedReq.headers?.[TRAP_HEADER.toLowerCase()]) {
    matches.push({
      rule: 'honeypot_trap_header', tags: ['honeypot', 'bot'], severity: 'high', category: 'honeypot',
      description: `Bot sent trap header ${TRAP_HEADER}`,
      author: 'ShieldWall', sourceFile: 'builtin:honeypot',
      matchedPatterns: [{ name: 'trap_header', matched: TRAP_HEADER }],
    });
  }

  return matches;
}

// Injects trap HTML into text/html responses before </body>
function injectMiddleware(options = {}) {
  const nonce = options.nonce || Math.random().toString(36).slice(2);

  return function honeypotInjector(req, res, next) {
    const originalEnd = res.end.bind(res);
    res.end = function(chunk, encoding) {
      const ct = res.getHeader('content-type') || '';
      if (ct.includes('text/html') && chunk) {
        let html = typeof chunk === 'string' ? chunk : chunk.toString(encoding || 'utf-8');
        const trap = generateTrapHTML(nonce);
        html = html.includes('</body>') ? html.replace('</body>', trap + '\n</body>') : html + trap;
        res.setHeader('Content-Length', Buffer.byteLength(html, 'utf-8'));
        return originalEnd(html, 'utf-8');
      }
      return originalEnd(chunk, encoding);
    };
    next();
  };
}

module.exports = { check, injectMiddleware, generateTrapHTML, TRAP_PATHS, HIDDEN_FIELD_NAME };

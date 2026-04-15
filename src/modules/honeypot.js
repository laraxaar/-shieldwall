'use strict';

const crypto = require('crypto');

// Honeypot traps — invisible HTML elements and fake endpoints that only bots interact with

// Динамические имена полей и заголовков генерируются при каждом запуске сервера.
// Это исключает возможность статического вырезания полей вроде `_hp_token` продвинутыми ботами.
const HIDDEN_FIELD_NAME = '_hp_' + crypto.randomBytes(4).toString('hex');
const TRAP_HEADER = 'X-Trap-' + crypto.randomBytes(4).toString('hex');

// Уязвимые пути по-умолчанию + динамические случайные пути
const BASE_TRAP_PATHS = [
  '/admin-panel', '/wp-admin', '/wp-login.php', '/administrator',
  '/phpmyadmin', '/api/internal/debug', '/api/v1/admin/users',
  '/backup', '/backup.sql', '/database.sql', '/db-backup.tar.gz',
  '/.env', '/.git/config', '/server-status', '/debug/vars',
  '/actuator/env', '/config.php.bak', '/xmlrpc.php', '/install.php',
];

// Генерируем 3 случайных фейковых API пути для усложнения фингерпринтинга
const DYNAMIC_TRAPS = Array.from({ length: 3 }, () => `/api/v2/` + crypto.randomBytes(4).toString('hex'));
const TRAP_PATHS = new Set([...BASE_TRAP_PATHS, ...DYNAMIC_TRAPS]);

function generateTrapHTML(nonce) {
  // Полиморфная генерация CSS и классов
  // Боты, парсящие DOM, не смогут найти элемент по статичным атрибутам
  const styles = [
    'position:absolute;left:-9999px;top:-9999px;height:0;width:0;overflow:hidden;pointer-events:none;opacity:0.01',
    'position:absolute;left:-8888px;top:-8888px;height:1px;width:1px;overflow:hidden;pointer-events:none;opacity:0',
    'position:fixed;left:-100vw;top:-100vh;height:0;width:0;opacity:0.001',
    'display:none !important;',
    'visibility:hidden;width:0;height:0;'
  ];
  
  const randomStyle = styles[Math.floor(Math.random() * styles.length)];
  const randomClass = 'cls_' + crypto.randomBytes(4).toString('hex');
  const randomTrapPath = DYNAMIC_TRAPS[Math.floor(Math.random() * DYNAMIC_TRAPS.length)];

  // Убран статичный aria-hidden="true", так как популярные скраперы его фильтруют.
  return `
<div class="${randomClass}" style="${randomStyle}">
  <form action="${randomTrapPath}" method="POST" tabindex="-1">
    <input type="text" name="username" value="" autocomplete="off" tabindex="-1">
    <input type="password" name="password" value="" autocomplete="off" tabindex="-1">
    <input type="hidden" name="${HIDDEN_FIELD_NAME}" value="${nonce}">
    <input type="email" name="email" value="" tabindex="-1">
    <button type="submit" tabindex="-1"></button>
  </form>
  <a href="/admin-panel">Admin</a>
  <a href="${randomTrapPath}">Users API</a>
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
  const nonce = options.nonce || crypto.randomBytes(8).toString('hex');

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

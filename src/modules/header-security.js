'use strict';

// Security headers (CSP, HSTS, Permissions-Policy, etc.) — built-in helmet.js alternative

const DEFAULTS = {
  contentSecurityPolicy: {
    enabled: true,
    directives: {
      'default-src': ["'self'"], 'script-src': ["'self'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:', 'https:'], 'font-src': ["'self'"],
      'connect-src': ["'self'"], 'frame-ancestors': ["'none'"],
      'base-uri': ["'self'"], 'form-action': ["'self'"], 'object-src': ["'none'"],
    },
  },
  hsts: { enabled: true, maxAge: 31536000, includeSubDomains: true, preload: false },
  nosniff: true,
  frameOptions: 'DENY',
  xssProtection: '0',
  referrerPolicy: 'strict-origin-when-cross-origin',
  dnsPrefetchControl: 'off',
  permittedCrossDomainPolicies: 'none',
  downloadOptions: 'noopen',
  permissionsPolicy: {
    enabled: true,
    features: { camera: [], microphone: [], geolocation: [], payment: [], usb: [], 'interest-cohort': [] },
  },
  crossOriginEmbedderPolicy: 'require-corp',
  crossOriginOpenerPolicy: 'same-origin',
  crossOriginResourcePolicy: 'same-origin',
  removeHeaders: ['X-Powered-By', 'Server'],
};

function buildCSP(d) { return Object.entries(d).map(([k, v]) => `${k} ${Array.isArray(v) ? v.join(' ') : v}`).join('; '); }
function buildPermissions(f) { return Object.entries(f).map(([k, a]) => a.length ? `${k}=(${a.join(' ')})` : `${k}=()`).join(', '); }

function deepMerge(t, s) {
  const o = { ...t };
  for (const k of Object.keys(s)) { o[k] = s[k] && typeof s[k] === 'object' && !Array.isArray(s[k]) ? deepMerge(t[k] || {}, s[k]) : s[k]; }
  return o;
}

function createMiddleware(userConfig = {}) {
  const c = deepMerge(DEFAULTS, userConfig);
  return function securityHeaders(_req, res) {
    if (c.contentSecurityPolicy?.enabled) res.setHeader('Content-Security-Policy', buildCSP(c.contentSecurityPolicy.directives));
    if (c.hsts?.enabled) {
      let v = `max-age=${c.hsts.maxAge}`; if (c.hsts.includeSubDomains) v += '; includeSubDomains'; if (c.hsts.preload) v += '; preload';
      res.setHeader('Strict-Transport-Security', v);
    }
    if (c.nosniff) res.setHeader('X-Content-Type-Options', 'nosniff');
    if (c.frameOptions) res.setHeader('X-Frame-Options', c.frameOptions);
    if (c.xssProtection !== false) res.setHeader('X-XSS-Protection', c.xssProtection || '0');
    if (c.referrerPolicy) res.setHeader('Referrer-Policy', c.referrerPolicy);
    if (c.dnsPrefetchControl) res.setHeader('X-DNS-Prefetch-Control', c.dnsPrefetchControl);
    if (c.permittedCrossDomainPolicies) res.setHeader('X-Permitted-Cross-Domain-Policies', c.permittedCrossDomainPolicies);
    if (c.downloadOptions) res.setHeader('X-Download-Options', c.downloadOptions);
    if (c.permissionsPolicy?.enabled) res.setHeader('Permissions-Policy', buildPermissions(c.permissionsPolicy.features));
    if (c.crossOriginEmbedderPolicy) res.setHeader('Cross-Origin-Embedder-Policy', c.crossOriginEmbedderPolicy);
    if (c.crossOriginOpenerPolicy) res.setHeader('Cross-Origin-Opener-Policy', c.crossOriginOpenerPolicy);
    if (c.crossOriginResourcePolicy) res.setHeader('Cross-Origin-Resource-Policy', c.crossOriginResourcePolicy);
    if (c.removeHeaders) c.removeHeaders.forEach(h => res.removeHeader(h));
  };
}

module.exports = { createMiddleware, DEFAULTS, buildCSP, buildPermissions };

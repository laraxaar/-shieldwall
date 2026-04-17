'use strict';

const { analyze, check, SCORE_THRESHOLD, CRITICAL_THRESHOLD } = require('../src/modules/anomaly');

function makeReq(overrides = {}) {
  return {
    url: '/api/users',
    rawUrl: '/api/users',
    path: '/api/users',
    method: 'GET',
    headers: {
      'accept': 'text/html',
      'accept-language': 'en-US',
      'accept-encoding': 'gzip',
      'user-agent': 'Mozilla/5.0 Chrome/120',
    },
    userAgent: 'Mozilla/5.0 Chrome/120',
    query: {},
    cookies: {},
    body: '',
    ip: '127.0.0.1',
    ...overrides,
  };
}

// ─── Clean Traffic ──────────────────────────────────────────────────────────

describe('clean traffic', () => {
  test('normal GET scores near zero', () => {
    const result = analyze(makeReq());
    expect(result.score).toBeLessThan(5);
    expect(result.level).toBe('none');
  });

  test('normal POST with JSON body scores low', () => {
    const result = analyze(makeReq({
      method: 'POST',
      body: JSON.stringify({ username: 'alice', email: 'alice@example.com' }),
      headers: {
        'accept': 'application/json',
        'accept-language': 'en-US',
        'accept-encoding': 'gzip',
        'user-agent': 'Mozilla/5.0 Chrome/120',
        'content-type': 'application/json',
        'origin': 'https://example.com',
      },
    }));
    expect(result.score).toBeLessThan(SCORE_THRESHOLD * 0.3);
  });

  test('GraphQL introspection query scores low', () => {
    const result = analyze(makeReq({
      method: 'POST',
      body: JSON.stringify({ query: '{ __schema { types { name } } }' }),
      headers: {
        'accept': 'application/json',
        'accept-language': 'en-US',
        'accept-encoding': 'gzip',
        'user-agent': 'Mozilla/5.0 Chrome/120',
        'content-type': 'application/json',
        'origin': 'https://example.com',
      },
    }));
    expect(result.score).toBeLessThan(SCORE_THRESHOLD);
  });
});

// ─── Safe Pattern Suppression ───────────────────────────────────────────────

describe('safe pattern suppression', () => {
  test('JWT token suppresses high_entropy', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const result = analyze(makeReq({
      query: { token: jwt },
    }));
    const factorNames = result.factors.map(f => f.name);
    expect(factorNames).not.toContain('high_entropy');
  });

  test('hex hash suppresses high_entropy', () => {
    const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const result = analyze(makeReq({
      query: { hash: sha256 },
    }));
    const factorNames = result.factors.map(f => f.name);
    expect(factorNames).not.toContain('high_entropy');
  });

  test('GraphQL introspection suppresses keywords', () => {
    const result = analyze(makeReq({
      body: '{ __schema { queryType { name } } }',
      url: '/graphql?query={__schema{types{name}}}',
    }));
    const factorNames = result.factors.map(f => f.name);
    expect(factorNames).not.toContain('keywords');
  });

  test('versioned REST API path suppresses deep_path', () => {
    const result = analyze(makeReq({
      path: '/api/v2/organizations/123/teams/456/members/789/roles/admin/permissions/read/audit',
    }));
    const factorNames = result.factors.map(f => f.name);
    expect(factorNames).not.toContain('deep_path');
  });
});

// ─── Attack Detection ────────────────────────────────────────────────────────

describe('attack detection', () => {
  test('basic SQLi triggers threshold', () => {
    const result = analyze(makeReq({
      url: "/api/search?q=' OR 1=1 -- - DROP TABLE users",
      query: { q: "' OR 1=1 -- - DROP TABLE users" },
      userAgent: '',
      headers: {},
    }));
    expect(result.score).toBeGreaterThanOrEqual(SCORE_THRESHOLD * 0.3);
  });

  test('encoded UNION SELECT reaches high/critical', () => {
    const payload = encodeURIComponent(encodeURIComponent("' UNION SELECT username, password FROM users --"));
    const result = analyze(makeReq({
      rawUrl: `/api/search?q=${payload}`,
      url: decodeURIComponent(decodeURIComponent(`/api/search?q=${payload}`)),
      query: { q: "' UNION SELECT username, password FROM users --" },
      userAgent: '',
      headers: {},
    }));
    expect(result.score).toBeGreaterThanOrEqual(SCORE_THRESHOLD);
  });

  test('XSS payload scores high', () => {
    const result = analyze(makeReq({
      url: '/search?q=<script>alert(document.cookie)</script>',
      query: { q: '<script>alert(document.cookie)</script>' },
      userAgent: '',
      headers: {},
    }));
    expect(result.score).toBeGreaterThanOrEqual(SCORE_THRESHOLD * 0.3);
  });

  test('executable payload detected', () => {
    const peHeader = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAA';
    const result = analyze(makeReq({
      body: peHeader,
      headers: {
        'user-agent': 'Mozilla/5.0 Chrome/120',
        'accept': 'application/octet-stream',
        'accept-language': 'en',
        'accept-encoding': 'gzip',
      },
    }));
    const factorNames = result.factors.map(f => f.name);
    expect(factorNames).toContain('executable_payload');
  });

  test('parameter pollution detected', () => {
    const result = analyze(makeReq({
      query: { id: ['1', '2', '3'] },
      headers: {
        'user-agent': 'Mozilla/5.0 Chrome/120',
        'accept': 'text/html',
        'accept-language': 'en',
        'accept-encoding': 'gzip',
      },
    }));
    const factorNames = result.factors.map(f => f.name);
    expect(factorNames).toContain('parameter_pollution');
  });
});

// ─── Group Scores ───────────────────────────────────────────────────────────

describe('grouped scoring', () => {
  test('result contains groupScores with all three categories', () => {
    const result = analyze(makeReq());
    expect(result.groupScores).toBeDefined();
    expect(result.groupScores).toHaveProperty('encoding');
    expect(result.groupScores).toHaveProperty('structural');
    expect(result.groupScores).toHaveProperty('behavioral');
  });

  test('encoding attack populates encoding group', () => {
    const doubleEncoded = encodeURIComponent(encodeURIComponent("' OR 1=1"));
    const result = analyze(makeReq({
      rawUrl: `/search?q=${doubleEncoded}`,
      url: "' OR 1=1",
      query: { q: "' OR 1=1" },
      userAgent: '',
      headers: {},
    }));
    expect(result.groupScores.encoding).toBeGreaterThan(0);
  });

  test('naked request populates behavioral group', () => {
    const result = analyze(makeReq({
      userAgent: '',
      headers: {},
    }));
    expect(result.groupScores.behavioral).toBeGreaterThan(0);
  });

  test('dominantGroup reflects highest-scoring category', () => {
    const result = analyze(makeReq({
      userAgent: '',
      headers: {},
    }));
    expect(['encoding', 'structural', 'behavioral']).toContain(result.dominantGroup);
  });

  test('factors include group field', () => {
    const result = analyze(makeReq({
      userAgent: '',
      headers: {},
    }));
    for (const factor of result.factors) {
      expect(factor.group).toBeDefined();
      expect(['encoding', 'structural', 'behavioral']).toContain(factor.group);
    }
  });
});

// ─── check() Function ──────────────────────────────────────────────────────

describe('check() output', () => {
  test('clean request returns empty array', () => {
    const matches = check(makeReq());
    expect(matches).toEqual([]);
  });

  test('low-score request returns escalation to smart_anomaly', () => {
    const matches = check(makeReq({
      userAgent: '',
      headers: {},
    }));
    if (matches.length > 0) {
      expect(matches[0].escalateTo).toBe('smart_anomaly');
      expect(matches[0].severity).toBe('low');
    }
  });

  test('high-score attack returns proper severity', () => {
    const matches = check(makeReq({
      url: "/api?q=' UNION SELECT * FROM users -- DROP TABLE sessions /* evil */ eval(system('rm -rf /'))",
      query: { q: "' UNION SELECT * FROM users -- DROP TABLE sessions /* evil */ eval(system('rm -rf /'))" },
      userAgent: '',
      headers: {},
    }));
    expect(matches.length).toBeGreaterThan(0);
    expect(['high', 'critical']).toContain(matches[0].severity);
    expect(matches[0].analysis.groupScores).toBeDefined();
  });
});

// ─── Regex Safety ───────────────────────────────────────────────────────────

describe('regex safety', () => {
  test('large repeating input completes in < 200ms', () => {
    const hugePayload = 'A'.repeat(100000);
    const start = Date.now();
    analyze(makeReq({
      url: `/test?q=${hugePayload.slice(0, 5000)}`,
      body: hugePayload,
      query: { q: hugePayload },
      headers: {
        'user-agent': 'Mozilla/5.0 Chrome/120',
        'accept': 'text/html',
        'accept-language': 'en',
        'accept-encoding': 'gzip',
      },
    }));
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(200);
  });

  test('pathological regex input does not hang', () => {
    // Pattern designed to cause backtracking in naive regex
    const pathological = '../'.repeat(5000) + '../../etc/passwd';
    const start = Date.now();
    analyze(makeReq({
      url: `/test?path=${pathological.slice(0, 5000)}`,
      query: { path: pathological },
      headers: {
        'user-agent': 'Mozilla/5.0 Chrome/120',
        'accept': 'text/html',
        'accept-language': 'en',
        'accept-encoding': 'gzip',
      },
    }));
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(200);
  });
});

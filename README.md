<p align="center">
  <img src="https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen?logo=node.js" alt="Node.js">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/dependencies-0-success" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/status-alpha-yellow" alt="Status">
</p>

<h1 align="center">🛡️ ShieldWall</h1>

<p align="center">
  <b>YARA-like WAF Engine for Node.js</b><br>
  <i>Behavioral anomaly detection + custom <code>.shield</code> rules for HTTP traffic</i>
</p>

---

> **⚠️ DISCLAIMER**
>
> This project is provided **"as-is"** for educational and research purposes.
> It requires **adaptation and tuning** for any specific deployment.  The
> authors accept **no responsibility** for vulnerabilities, false positives,
> or security incidents in applications that use this middleware.  Always
> combine ShieldWall with other security layers — it is not a silver bullet.

---

## How It Works

ShieldWall takes a **layered approach** instead of trying to enumerate every
known attack signature:

```
HTTP Request
  │
  ├─ 1. Multi-layer Decoder     URL / HTML / Unicode / Base64 / null bytes
  ├─ 2. Anomaly Scoring         character distribution, encoding depth, structural oddities
  ├─ 3. Honeypot Traps          invisible forms, fake endpoints, bot detection
  ├─ 4. Baseline Patterns       minimal structural patterns as safety net
  ├─ 5. .shield Rule Engine     YARA-inspired DSL for custom detection logic
  ├─ 6. Rate Limiter            sliding window per-IP
  ├─ 7. Brute-Force Guard       progressive backoff on auth endpoints
  └─ 8. Security Headers        CSP, HSTS, X-Frame-Options, etc.
```

The key insight: instead of hardcoding thousands of exploit payloads, ShieldWall
asks *"does this request look normal?"*  The **anomaly scorer** assigns a
suspicion score based on behavioral signals (encoding layers, character entropy,
nesting depth, mixed encoding schemes), while **baseline patterns** and
**.shield rules** catch the most obvious structural attack shapes.

This makes it **database-agnostic** and **adaptive** — it works against SQL,
NoSQL, LDAP, GraphQL, or any other injection target.

---

## Installation

```bash
npm install shieldwall
```

## Quick Start

```javascript
const express = require('express');
const shieldwall = require('shieldwall');

const app = express();
app.use(express.json());

app.use(shieldwall({
  mode: 'block',        // 'block' or 'detect' (log only)
  dashboard: { port: 9090 },
  rateLimit: { max: 100 },
  bruteForce: { maxAttempts: 5 },
}));

app.get('/', (req, res) => {
  res.json({ message: 'Protected by ShieldWall 🛡️' });
});

app.listen(3000);
```

---

## .shield Rule Syntax

Write custom detection rules in a YARA-inspired DSL:

```
rule my_detection : tag {
    meta:
        author      = "You"
        description = "What this catches and why"
        severity    = "critical"

    target:
        $url  = request.url
        $body = request.body

    strings:
        $pattern = /suspicious_regex/i

    condition:
        $pattern in $url or $pattern in $body
}
```

### Targets

| Target | Description |
|--------|-------------|
| `request.url` | Full decoded URL |
| `request.body` | Request body |
| `request.query` | Query string parameters |
| `request.headers` | All headers |
| `request.cookies` | Cookie values |
| `request.useragent` | User-Agent string |
| `request.raw_url` | URL before decoding (for evasion detection) |

### Condition Operators

`and`, `or`, `not`, `in` (target-scoped match), `any of them`, `all of them`, `( )` grouping.

Rules can be loaded from files, directories, or inline strings — see examples.

---

## Modules

| Module | Approach |
|--------|----------|
| **Anomaly Scoring** | Behavioral heuristics — encoding layers, char density, nesting depth, mixed schemes |
| **Honeypot** | Invisible HTML traps, fake admin panels, fake APIs — flags anything that interacts |
| **Injection** | Structural patterns (context breaks + keywords) — database-agnostic |
| **XSS** | HTML execution shapes (tags, handlers, protocol, DOM sinks) |
| **Path Traversal** | Decoded traversal + encoding evasion detection on raw URL |
| **Command Injection** | Shell metacharacter + command name structural pair |
| **Scanner Detection** | User-Agent fingerprints and out-of-band callback domains |
| **Protocol Abuse** | HTTP smuggling, SSRF, CRLF, host header poisoning |
| **Rate Limiter** | Sliding window per-IP with auto-blocking |
| **Brute-Force Guard** | Progressive backoff on sensitive endpoints |
| **Security Headers** | CSP, HSTS, Permissions-Policy, etc. (helmet.js alternative) |

---

## Honeypot

ShieldWall automatically injects invisible HTML traps into your pages:

- Hidden forms that humans can't see but bots auto-fill
- Fake links to `/admin-panel`, `/.env`, `/.git/config`
- Fake API endpoints like `/api/internal/debug`

Any interaction with these traps immediately flags the client as a bot.

---

## Dashboard

Real-time monitoring at `http://localhost:9090`:

- Live attack feed with severity indicators
- Why each request was blocked (human-readable explanations)
- Severity breakdown, top attack types, top attacker IPs
- WebSocket-powered — updates instantly

---

## Configuration

```javascript
shieldwall({
  mode: 'block',                    // 'block' | 'detect'
  logLevel: 'info',                 // 'error' | 'warn' | 'info' | 'debug'
  jsonLogs: false,                  // structured JSON output
  rulesDir: './rules',              // .shield files directory
  customRules: '...',               // inline .shield string
  customRulesFiles: [],             // additional .shield file paths
  blockStatusCode: 403,
  blockMessage: null,               // string or function(matches)
  trustProxy: false,
  excludePaths: ['/health'],
  excludeIPs: ['127.0.0.1'],
  modules: { anomaly: true, honeypot: true, sqli: true, xss: true, pathTraversal: true, commandInjection: true },
  rateLimit: { windowMs: 60000, max: 100 },
  bruteForce: { maxAttempts: 5, sensitivePaths: ['/login'] },
  dashboard: { port: 9090 },
  headers: { hsts: { maxAge: 31536000 } },
  honeypot: true,                   // inject HTML traps into responses
});
```

### Programmatic Access

```javascript
const waf = shieldwall({ ... });

waf.on('threat', (event) => {
  // event.matches — what triggered
  // event.request — IP, method, URL
  // send to Slack, Discord, webhook, SIEM...
});

waf.getStats();      // request/block/threat counters
waf.reloadRules();   // hot-reload .shield files
```

---

## Logging

Every blocked request produces a structured log explaining:

```
[SHIELDWALL] 🔴 BLOCKED | anomaly_detection [critical] | 192.168.1.50 POST /api/data
  ├─ Why: Anomaly score 28/30: multi_layer_encoding, unusual_char_density, comment_syntax
  └─ Evidence: [multi_layer_encoding] 3 layers of URL encoding — likely evasion attempt
```

JSON mode (`jsonLogs: true`) outputs machine-parseable entries for SIEM integration.

---

## License

MIT — see [LICENSE](./LICENSE)

---

<p align="center">
  <i>Built for the security research community.<br>
  This is a tool, not a product — tune it for your environment.</i>
</p>

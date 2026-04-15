'use strict';

// Sliding window rate limiter with per-IP auto-blocking

class RateLimiter {
  constructor(options = {}) {
    this.windowMs = options.windowMs || 60_000;
    this.max = options.max || 100;
    this.blockDuration = options.blockDuration || 300_000;
    this.keyGenerator = options.keyGenerator || this._defaultKey;
    this.skipPaths = options.skipPaths || [];
    this.trustProxy = options.trustProxy || false;
    this._requests = new Map();
    this._blocked = new Map();
    this._gc = setInterval(() => this._cleanup(), 60_000);
    this._gc.unref?.();
  }

  _defaultKey(req) {
    if (this.trustProxy) { const f = req.headers?.['x-forwarded-for']; if (f) return f.split(',')[0].trim(); }
    return req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || 'unknown';
  }

  check(req) {
    const key = this.keyGenerator.call(this, req);
    const now = Date.now();
    const path = req.path || req.url?.split('?')[0] || '';
    for (const s of this.skipPaths) { if (path.startsWith(s)) return { limited: false, ip: key, count: 0, max: this.max, retryAfter: 0 }; }

    const bu = this._blocked.get(key);
    if (bu && now < bu) return { limited: true, ip: key, count: this.max, max: this.max, retryAfter: bu - now };
    if (bu) this._blocked.delete(key);

    let reqs = this._requests.get(key);
    if (!reqs) { reqs = []; this._requests.set(key, reqs); }
    while (reqs.length && reqs[0] < now - this.windowMs) reqs.shift();
    reqs.push(now);

    if (reqs.length > this.max) {
      this._blocked.set(key, now + this.blockDuration);
      return { limited: true, ip: key, count: reqs.length, max: this.max, retryAfter: this.blockDuration };
    }
    return { limited: false, ip: key, count: reqs.length, max: this.max, retryAfter: 0, remaining: this.max - reqs.length };
  }

  blockIP(ip, ms) { this._blocked.set(ip, Date.now() + (ms || this.blockDuration)); }
  unblockIP(ip) { this._blocked.delete(ip); this._requests.delete(ip); }

  getBlockedIPs() {
    const now = Date.now(), list = [];
    for (const [ip, u] of this._blocked) { if (now < u) list.push({ ip, blockedUntil: new Date(u).toISOString() }); }
    return list;
  }

  _cleanup() {
    const cutoff = Date.now() - this.windowMs;
    for (const [k, r] of this._requests) { const v = r.filter(t => t > cutoff); if (!v.length) this._requests.delete(k); else this._requests.set(k, v); }
    const now = Date.now();
    for (const [k, u] of this._blocked) { if (now >= u) this._blocked.delete(k); }
  }

  destroy() { clearInterval(this._gc); this._requests.clear(); this._blocked.clear(); }
}

module.exports = RateLimiter;

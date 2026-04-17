'use strict';

/**
 * @file rate-limiter.js
 * @description Distributed Sliding Window Rate Limiting Engine.
 * 
 * ROLE IN ARCHITECTURE:
 * Primary L4/L7 volumetric barrier. Evaluates traffic speeds prior to heavy heuristic
 * inspection. Implements abstract MemStore patterns mapping to Redis/Memcached.
 * 
 * DATA FLOW:
 * [Middleware] -> `limiter.check(req)` -> Maps `req.ip` state -> Emits true/false throttle bounds.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION:
 * Integrates `trustProxy` routing schemas to prevent upstream Load Balancer (Cloudflare) IPs 
 * from being banned identically, protecting proxy networks from false aggregate drops.
 */
/**
 * Default In-Memory Store for the Rate Limiter.
 * Can be replaced with a RedisStore or any KV store matching this interface
 * to support horizontal scaling across instances.
 */
class MemoryStore {
  constructor(windowMs) {
    this.windowMs = windowMs;
    this._requests = new Map();
    this._blocked = new Map();
  }

  async increment(key) {
    const now = Date.now();
    let reqs = this._requests.get(key) || [];
    const cutoff = now - this.windowMs;
    reqs = reqs.filter(t => t > cutoff);
    reqs.push(now);
    this._requests.set(key, reqs);
    return reqs.length;
  }

  async block(key, blockDuration) {
    this._blocked.set(key, Date.now() + blockDuration);
  }

  async isBlocked(key) {
    const bu = this._blocked.get(key);
    if (!bu) return 0;
    if (Date.now() < bu) return bu;
    this._blocked.delete(key);
    return 0;
  }

  async cleanup() {
    const cutoff = Date.now() - this.windowMs;
    for (const [k, r] of this._requests) {
      const v = r.filter(t => t > cutoff);
      if (!v.length) this._requests.delete(k);
      else this._requests.set(k, v);
    }
    const now = Date.now();
    for (const [k, u] of this._blocked) {
      if (now >= u) this._blocked.delete(k);
    }
  }

  async getBlockedIPs() {
    const now = Date.now(), list = [];
    for (const [ip, u] of this._blocked) {
      if (now < u) list.push({ ip, blockedUntil: new Date(u).toISOString() });
    }
    return list;
  }

  async unblock(key) {
    this._blocked.delete(key);
    this._requests.delete(key);
  }

  async clear() {
    this._requests.clear();
    this._blocked.clear();
  }
}

class RateLimiter {
  constructor(options = {}) {
    this.windowMs = options.windowMs || 60_000;
    this.max = options.max || 100;
    this.blockDuration = options.blockDuration || 300_000;
    this.keyGenerator = options.keyGenerator || this._defaultKey;
    this.skipPaths = options.skipPaths || [];
    this.trustProxy = options.trustProxy || false;
    
    // Abstract the state layer. Enables easy swap to Redis/Memcached.
    this.store = options.store || new MemoryStore(this.windowMs);

    this._gc = setInterval(() => this.store.cleanup(), 60_000);
    this._gc.unref?.();
  }

  _defaultKey(req) {
    if (this.trustProxy) { const f = req.headers?.['x-forwarded-for']; if (f) return f.split(',')[0].trim(); }
    return req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || 'unknown';
  }

  async check(req) {
    const key = this.keyGenerator.call(this, req);
    const now = Date.now();
    const path = req.path || req.url?.split('?')[0] || '';
    
    for (const s of this.skipPaths) { 
      if (path.startsWith(s)) return { limited: false, ip: key, count: 0, max: this.max, retryAfter: 0 }; 
    }

    const blockUntil = await this.store.isBlocked(key);
    if (blockUntil > 0) {
      return { limited: true, ip: key, count: this.max, max: this.max, retryAfter: blockUntil - now };
    }

    const count = await this.store.increment(key);

    if (count > this.max) {
      await this.store.block(key, this.blockDuration);
      return { limited: true, ip: key, count, max: this.max, retryAfter: this.blockDuration };
    }
    
    return { limited: false, ip: key, count, max: this.max, retryAfter: 0, remaining: this.max - count };
  }

  // Fallbacks for backwards compatibility — ideally should be awaited downstream
  blockIP(ip, ms) { this.store.block(ip, ms || this.blockDuration); }
  unblockIP(ip) { this.store.unblock(ip); }

  async getBlockedIPs() { return await this.store.getBlockedIPs(); }

  destroy() { 
    clearInterval(this._gc); 
    this.store.clear(); 
  }
}

module.exports = { RateLimiter, MemoryStore };

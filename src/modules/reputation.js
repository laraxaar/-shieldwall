'use strict';

/**
 * Reputation Engine (Threat Intel Layer)
 * 
 * ARCHITECTURAL CONTEXT (2026 Standard):
 * Acts as a mini threat-intel system maintaining a sliding window of localized
 * threat perception. Features TTL, LRU bounds, decay, and severity-weighted scoring.
 * 
 * ⚠️ ARCHITECTURAL LIMITATION (IP as Primary Key):
 * IP address is a structurally weak axis of trust due to NAT, mobile networks, 
 * CGNAT, and proxies. This engine treats IP reputation as a *signal*, not 
 * ground truth.
 * 
 * FUTURE ROADMAP:
 * Migrate primary key from `IP` to dynamic `ASN + Behavior Cluster` + `Device Fingerprint`.
 * The scoring must evolve from additive thresholds to probabilistic decay based on
 * valid session ratios.
 */

const LRU = require('lru-cache');

const REPUTATION_TTL = 24 * 60 * 60 * 1000;
const MAX_ENTRIES = 10000;

const SEVERITY_SCORES = {
  critical: 100,
  high: 50,
  medium: 20,
  low: 10,
  info: 1,
};

const HALF_LIFE_HOURS = 24;
const LAMBDA = Math.LN2 / HALF_LIFE_HOURS;

const reputationCache = new LRU({
  max: MAX_ENTRIES,
  ttl: REPUTATION_TTL,
  updateAgeOnGet: true,
});

class ReputationEngine {
  constructor() {
    this.cache = reputationCache;
  }

  _getKey(ip) {
    return `rep:${ip}`;
  }

  _calculateCurrentScore(data, now = Date.now()) {
    if (!data.lastSeen) return data.score;
    const hoursPassed = (now - data.lastSeen) / (1000 * 60 * 60);
    // Exponential decay application
    let currentScore = data.score * Math.exp(-LAMBDA * hoursPassed);
    
    // Prevent floating point dust
    if (currentScore < 1) currentScore = 0;
    
    return currentScore;
  }

  recordIncident(ip, category, severity) {
    if (!ip) return;
    const now = Date.now();
    const key = this._getKey(ip);
    
    const existing = this.cache.get(key) || {
      score: 0,
      incidents: [],
      firstSeen: now,
      lastSeen: now,
    };

    // Apply temporal decay to the old score before adding the new penalty
    existing.score = this._calculateCurrentScore(existing, now);

    const points = SEVERITY_SCORES[severity] || 1;
    existing.score = Math.min(existing.score + points, 1000);
    existing.lastSeen = now;

    existing.incidents.push({
      category,
      severity,
      timestamp: now,
    });

    if (existing.incidents.length > 50) existing.incidents.shift();

    this.cache.set(key, existing);
  }

  recordTrust(ip, category, trustValue = 10) {
    if (!ip) return;
    const now = Date.now();
    const key = this._getKey(ip);
    
    const data = this.cache.get(key);
    if (!data) return; // We only reduce risk for users that actually have a risk profile.

    data.score = this._calculateCurrentScore(data, now);
    
    // Subtract trust value, floored at 0
    data.score = Math.max(0, data.score - trustValue);
    data.lastSeen = now;

    this.cache.set(key, data);
  }

  getReputation(ip) {
    if (!ip) return { score: 0, trust: 'unknown' };

    const key = this._getKey(ip);
    const data = this.cache.get(key);

    if (!data) {
      return { score: 0, trust: 'unknown', incidents: [] };
    }

    // Dynamic just-in-time calculation
    const currentScore = this._calculateCurrentScore(data);
    const trustLevel = this._calculateTrust(currentScore);

    return {
      score: +currentScore.toFixed(2),
      trust: trustLevel,
      firstSeen: data.firstSeen,
      lastSeen: data.lastSeen,
      incidentCount: data.incidents.length,
      categories: this._extractCategories(data.incidents),
      recentIncidents: data.incidents.slice(-5),
    };
  }

  _calculateTrust(score) {
    if (score >= 200) return 'blocked';
    if (score >= 100) return 'suspicious';
    if (score >= 50) return 'caution';
    if (score > 0) return 'low';
    return 'neutral';
  }

  _extractCategories(incidents) {
    const cats = new Map();
    for (const inc of incidents) {
      const count = cats.get(inc.category) || 0;
      cats.set(inc.category, count + 1);
    }
    return Object.fromEntries(cats);
  }

  shouldEnforceStrictCheck(ip) {
    const rep = this.getReputation(ip);
    return rep.trust === 'blocked' || rep.trust === 'suspicious';
  }

  getAllBlockedIPs() {
    const blocked = [];
    for (const [key, value] of this.cache.entries()) {
      const dynamicScore = this._calculateCurrentScore(value);
      if (this._calculateTrust(dynamicScore) === 'blocked') {
        blocked.push({
          ip: key.replace('rep:', ''),
          score: +dynamicScore.toFixed(2),
          incidents: value.incidents.length,
        });
      }
    }
    return blocked;
  }
} // Remove decayReputation() entirely

const engine = new ReputationEngine();

function check(decodedReq) {
  const ip = decodedReq.ip;
  if (!ip) return [];

  const rep = engine.getReputation(ip);

  if (rep.trust === 'blocked') {
    return [{
      rule: 'reputation_block',
      tags: ['reputation', 'blocklist'],
      severity: 'critical',
      category: 'reputation',
      description: `IP ${ip} has critical reputation score (${rep.score}) - previous incidents: ${rep.incidentCount}`,
      author: 'shieldwall-core',
      sourceFile: 'builtin:reputation',
      analysis: {
        reputationScore: rep.score,
        trustLevel: rep.trust,
        incidentCategories: rep.categories,
      },
      matchedPatterns: Object.keys(rep.categories).map(cat => ({
        name: `prev_${cat}`,
        matched: `${rep.categories[cat]} incidents`,
      })),
    }];
  }

  if (rep.trust === 'suspicious') {
    return [{
      rule: 'reputation_suspicious',
      tags: ['reputation', 'warning'],
      severity: 'high',
      category: 'reputation',
      description: `IP ${ip} has suspicious reputation (${rep.score}) - strict checks enforced`,
      author: 'shieldwall-core',
      sourceFile: 'builtin:reputation',
      analysis: {
        reputationScore: rep.score,
        trustLevel: rep.trust,
      },
      matchedPatterns: [{ name: 'suspicious_reputation', matched: `score ${rep.score}` }],
    }];
  }

  return [];
}

function record(ip, category, severity) {
  engine.recordIncident(ip, category, severity);
}

function recordTrust(ip, category, trustValue) {
  engine.recordTrust(ip, category, trustValue);
}

function getReputation(ip) {
  return engine.getReputation(ip);
}

module.exports = { check, record, recordTrust, getReputation, ReputationEngine };

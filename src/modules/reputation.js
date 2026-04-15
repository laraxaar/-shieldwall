'use strict';

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

  recordIncident(ip, category, severity) {
    if (!ip) return;

    const key = this._getKey(ip);
    const existing = this.cache.get(key) || {
      score: 0,
      incidents: [],
      firstSeen: Date.now(),
      lastSeen: Date.now(),
    };

    const points = SEVERITY_SCORES[severity] || 1;
    existing.score = Math.min(existing.score + points, 1000);
    existing.lastSeen = Date.now();

    existing.incidents.push({
      category,
      severity,
      timestamp: Date.now(),
    });

    if (existing.incidents.length > 50) {
      existing.incidents.shift();
    }

    this.cache.set(key, existing);
  }

  getReputation(ip) {
    if (!ip) return { score: 0, trust: 'unknown' };

    const key = this._getKey(ip);
    const data = this.cache.get(key);

    if (!data) {
      return { score: 0, trust: 'unknown', incidents: [] };
    }

    const trustLevel = this._calculateTrust(data.score);

    return {
      score: data.score,
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
      if (this._calculateTrust(value.score) === 'blocked') {
        blocked.push({
          ip: key.replace('rep:', ''),
          score: value.score,
          incidents: value.incidents.length,
        });
      }
    }
    return blocked;
  }

  decayReputation(ip, factor = 0.9) {
    if (!ip) return;

    const key = this._getKey(ip);
    const data = this.cache.get(key);
    if (!data) return;

    data.score = Math.floor(data.score * factor);
    if (data.score < 5) {
      this.cache.delete(key);
    } else {
      this.cache.set(key, data);
    }
  }
}

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
      author: 'laraxaar',
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
      author: 'laraxaar',
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

function getReputation(ip) {
  return engine.getReputation(ip);
}

module.exports = { check, record, getReputation, ReputationEngine };

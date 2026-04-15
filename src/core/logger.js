'use strict';

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const COLORS = { error: '\x1b[31m', warn: '\x1b[33m', info: '\x1b[36m', debug: '\x1b[90m' };
const SEVERITY_ICONS = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: 'ℹ️' };
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

class Logger {
  constructor(options = {}) {
    this.level = LEVELS[options.level] ?? LEVELS.info;
    this.silent = options.silent || false;
    this.jsonOutput = options.json || false;
    this.onEvent = options.onEvent || null;
    this.history = [];
    this.maxHistory = options.maxHistory || 1000;
  }

  _log(level, message, data = null) {
    if (this.silent || LEVELS[level] > this.level) return;

    const entry = { timestamp: new Date().toISOString(), level, message, ...(data && { data }) };
    this._store(entry);

    if (this.jsonOutput) {
      console.log(JSON.stringify(entry));
    } else {
      const c = COLORS[level] || '';
      console.log(`${c}${BOLD}[SHIELDWALL]${RESET} ${c}[${level.toUpperCase()}]${RESET} \x1b[90m${entry.timestamp}${RESET} ${message}`);
      if (data) console.log(`${c}  └─${RESET}`, data);
    }
  }

  error(msg, data) { this._log('error', msg, data); }
  warn(msg, data)  { this._log('warn', msg, data); }
  info(msg, data)  { this._log('info', msg, data); }
  debug(msg, data) { this._log('debug', msg, data); }

  // Structured security event with WHY/Evidence explanation
  attack(event) {
    const icon = SEVERITY_ICONS[event.severity] || '⚠️';
    const action = event.blocked ? 'BLOCKED' : 'DETECTED';

    const entry = {
      timestamp: new Date().toISOString(),
      level: 'warn',
      type: 'attack',
      action: event.blocked ? 'blocked' : 'detected',
      rule: event.rule || 'unknown',
      severity: event.severity || 'medium',
      category: event.category || 'unknown',
      ip: event.ip || 'unknown',
      method: event.method || 'GET',
      url: event.url || '/',
      description: event.description || '',
      matchedPattern: event.matchedPattern || null,
      analysis: event.analysis || null,
    };

    this._store(entry);

    if (!this.silent) {
      if (this.jsonOutput) {
        console.log(JSON.stringify(entry));
      } else {
        console.log(`${BOLD}${COLORS.warn}[SHIELDWALL]${RESET} ${icon} ${action} | ${BOLD}${entry.rule}${RESET} [${entry.severity}] | ${entry.ip} ${entry.method} ${entry.url}`);
        if (entry.description) console.log(`  ├─ Why: ${entry.description}`);
        if (entry.matchedPattern) console.log(`  └─ Evidence: ${entry.matchedPattern}`);
      }
    }
  }

  _store(entry) {
    this.history.push(entry);
    if (this.history.length > this.maxHistory) this.history.shift();
    if (this.onEvent) this.onEvent(entry);
  }

  getHistory(count = 100) { return this.history.slice(-count); }

  getStats() {
    const attacks = this.history.filter(e => e.type === 'attack');
    const stats = {
      total: attacks.length,
      blocked: attacks.filter(e => e.action === 'blocked').length,
      detected: attacks.filter(e => e.action === 'detected').length,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      byCategory: {},
      topIPs: {},
      topRules: {},
    };
    for (const a of attacks) {
      if (stats.bySeverity[a.severity] !== undefined) stats.bySeverity[a.severity]++;
      stats.byCategory[a.category] = (stats.byCategory[a.category] || 0) + 1;
      stats.topIPs[a.ip] = (stats.topIPs[a.ip] || 0) + 1;
      stats.topRules[a.rule] = (stats.topRules[a.rule] || 0) + 1;
    }
    return stats;
  }

  clearHistory() { this.history = []; }
}

module.exports = Logger;

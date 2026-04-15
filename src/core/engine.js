'use strict';

const { EventEmitter } = require('events');
const path = require('path');
const { decodeRequest } = require('./decoder');
const { parseRules, loadRulesFromDir } = require('./rule-parser');
const { matchAllRules } = require('./rule-matcher');
const Logger = require('./logger');
const ReportingEngine = require('./reporting');

const DEFAULT_RULES_DIR = path.join(__dirname, '..', '..', 'rules');
const SEVERITY_PRIORITY = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

class ShieldWallEngine extends EventEmitter {
  constructor(options = {}) {
    super();

    this.options = {
      mode: options.mode || 'block',
      logLevel: options.logLevel || 'info',
      jsonLogs: options.jsonLogs || false,
      silent: options.silent || false,
      rulesDir: options.rulesDir || DEFAULT_RULES_DIR,
      customRules: options.customRules || null,
      customRulesFiles: options.customRulesFiles || [],
      blockStatusCode: options.blockStatusCode || 403,
      blockMessage: options.blockMessage || null,
      trustProxy: options.trustProxy || false,
      excludePaths: options.excludePaths || [],
      excludeIPs: options.excludeIPs || [],
      modules: {
        anomaly: true, smartAnomaly: true, honeypot: true, sqli: true, xss: true,
        pathTraversal: true, commandInjection: true,
        botDetection: true, sessionAnomaly: true, apiAbuse: true,
        ddosProtection: true, fingerprinter: true, reputation: true,
        ...(options.modules || {}),
      },
    };

    this.logger = new Logger({
      level: this.options.logLevel,
      silent: this.options.silent,
      json: this.options.jsonLogs,
      maxHistory: options.maxHistory || 10000,
      onEvent: (event) => this.emit('log', event),
    });

    this.rules = [];
    this._loadRules();

    this.modules = [];
    this._loadModules();

    this.stats = { totalRequests: 0, blockedRequests: 0, detectedThreats: 0, startTime: Date.now() };

    this.reporting = null;
    if (options.reporting !== false) {
      this.reporting = new ReportingEngine({
        enabled: true,
        reportsDir: options.reportsDir,
        maxStoredReports: options.maxStoredReports,
        logger: this.logger,
        onReport: (report) => this.emit('report', report),
      });
    }

    this.logger.info('Engine initialized', {
      mode: this.options.mode,
      rulesLoaded: this.rules.length,
      modulesActive: this.modules.map(m => m.name),
      reportingEnabled: !!this.reporting,
    });
  }

  _loadRules() {
    try {
      const rules = loadRulesFromDir(this.options.rulesDir);
      this.rules.push(...rules);
    } catch (err) {
      this.logger.warn(`Could not load default rules: ${err.message}`);
    }

    for (const filePath of this.options.customRulesFiles) {
      try {
        const { parseRuleFile } = require('./rule-parser');
        this.rules.push(...parseRuleFile(filePath));
      } catch (err) {
        this.logger.error(`Error loading ${filePath}: ${err.message}`);
      }
    }

    if (this.options.customRules) {
      try { this.rules.push(...parseRules(this.options.customRules)); }
      catch (err) { this.logger.error(`Error parsing inline rules: ${err.message}`); }
    }
  }

  _loadModules() {
    const map = {
      anomaly: '../modules/anomaly',
      smartAnomaly: '../modules/smart-anomaly',
      honeypot: '../modules/honeypot',
      sqli: '../modules/sqli',
      xss: '../modules/xss',
      pathTraversal: '../modules/path-traversal',
      commandInjection: '../modules/command-injection',
      botDetection: '../modules/bot-detection',
      sessionAnomaly: '../modules/session-anomaly',
      apiAbuse: '../modules/api-abuse',
      ddosProtection: '../modules/ddos-protection',
      fingerprinter: '../modules/fingerprinter',
      reputation: '../modules/reputation',
    };

    for (const [name, modulePath] of Object.entries(map)) {
      if (!this.options.modules[name]) continue;
      try {
        const mod = require(modulePath);
        this.modules.push({ name, check: mod.check, module: mod });
      } catch (err) {
        this.logger.warn(`Module "${name}" not loaded: ${err.message}`);
      }
    }
  }

  // Pipeline: decode → modules → rules → verdict
  analyze(req) {
    this.stats.totalRequests++;
    if (this._isExcluded(req)) return { blocked: false, matches: [], decodedReq: null };

    const decodedReq = decodeRequest(req);
    const allMatches = [];

    for (const mod of this.modules) {
      try {
        const results = mod.check(decodedReq);
        if (results?.length) allMatches.push(...results);
      } catch (err) {
        this.logger.error(`Module "${mod.name}" threw: ${err.message}`);
      }
    }

    allMatches.push(...matchAllRules(this.rules, decodedReq));

    if (!allMatches.length) return { blocked: false, matches: [], decodedReq };

    const blocked = this.options.mode === 'block';
    const highestSeverity = this._getHighestSeverity(allMatches);

    for (const match of allMatches) {
      this.logger.attack({
        blocked,
        rule: match.rule,
        severity: match.severity,
        category: match.category,
        ip: decodedReq.ip,
        method: decodedReq.method,
        url: decodedReq.rawUrl,
        description: match.description,
        matchedPattern: this._formatEvidence(match),
        analysis: match.analysis || null,
      });

      if (this.options.modules.reputation !== false) {
        try {
          const { record } = require('../modules/reputation');
          record(decodedReq.ip, match.category, match.severity);
        } catch {}
      }
    }

    this.stats.detectedThreats += allMatches.length;
    if (blocked) this.stats.blockedRequests++;

    this.emit('threat', {
      blocked, matches: allMatches, highestSeverity,
      request: { ip: decodedReq.ip, method: decodedReq.method, url: decodedReq.rawUrl, userAgent: decodedReq.userAgent },
    });

    return { blocked, matches: allMatches, decodedReq, highestSeverity };
  }

  _formatEvidence(match) {
    if (match.analysis?.factors) {
      return match.analysis.factors.map(f => `[${f.name}] ${f.detail}`).join(' | ');
    }
    if (match.matchedPatterns?.length) {
      return match.matchedPatterns.map(p => `${p.name}: "${p.matched}"`).join(', ');
    }
    return '';
  }

  _isExcluded(req) {
    const p = req.path || req.url?.split('?')[0] || '';
    const ip = req.ip || req.connection?.remoteAddress || '';
    for (const ex of this.options.excludePaths) {
      if (typeof ex === 'string' && p.startsWith(ex)) return true;
      if (ex instanceof RegExp && ex.test(p)) return true;
    }
    return this.options.excludeIPs.includes(ip);
  }

  _getHighestSeverity(matches) {
    let h = 'info', hp = 0;
    for (const m of matches) { const p = SEVERITY_PRIORITY[m.severity] || 0; if (p > hp) { hp = p; h = m.severity; } }
    return h;
  }

  getBlockResponse(matches, severity) {
    if (this.options.blockMessage) {
      return typeof this.options.blockMessage === 'function'
        ? this.options.blockMessage(matches) : this.options.blockMessage;
    }
    return JSON.stringify({
      error: 'Request Blocked',
      reason: 'ShieldWall detected a potential security threat',
      severity,
      rules: matches.map(m => m.rule),
      timestamp: new Date().toISOString(),
    });
  }

  getStats() {
    return {
      ...this.stats,
      uptime: Date.now() - this.stats.startTime,
      rulesLoaded: this.rules.length,
      modulesActive: this.modules.map(m => m.name),
      logStats: this.logger.getStats(),
      reportsAvailable: this.reporting?.getStoredReports().length || 0,
    };
  }

  getReport(days = 14) {
    if (!this.reporting) return null;
    return this.reporting.generateManualReport(this.logger.history, days, `manual-${days}d`);
  }

  getStoredReports() {
    return this.reporting?.getStoredReports() || [];
  }

  reloadRules() {
    this.rules = [];
    this._loadRules();
    this.logger.info(`Rules reloaded — ${this.rules.length} active`);
    this.emit('rules-reloaded', this.rules.length);
  }
}

module.exports = ShieldWallEngine;

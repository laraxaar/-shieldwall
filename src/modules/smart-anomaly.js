'use strict';

const { loadRulesFromDir } = require('../core/rule-parser');
const path = require('path');

const ANOMALY_HISTORY = new Map();
const MAX_HISTORY = 1000;
const HISTORY_WINDOW = 5 * 60 * 1000;

class SmartAnomalyDetector {
  constructor(rulesDir) {
    this.rulesDir = rulesDir || path.join(__dirname, '..', '..', 'rules');
    this.rules = [];
    this.patternProfiles = new Map();
    this.categoryProfiles = new Map();
    this._loadRules();
  }

  _loadRules() {
    try {
      this.rules = loadRulesFromDir(this.rulesDir);
      this._buildProfiles();
    } catch (err) {
      console.error('[SmartAnomaly] Failed to load rules:', err.message);
    }
  }

  _buildProfiles() {
    for (const rule of this.rules) {
      const profile = {
        name: rule.name,
        category: rule.tags?.[0] || 'unknown',
        severity: rule.meta?.severity || 'medium',
        description: rule.meta?.description || '',
        targets: Object.values(rule.targets || {}),
        patterns: Object.entries(rule.strings || {}).map(([name, def]) => ({
          name,
          type: def.type,
          pattern: def.pattern || def.value,
          compiled: def.compiled,
        })),
        condition: rule.condition,
      };

      this.patternProfiles.set(rule.name, profile);

      const cat = profile.category;
      if (!this.categoryProfiles.has(cat)) {
        this.categoryProfiles.set(cat, { patterns: [], severities: [], rules: [] });
      }
      const cp = this.categoryProfiles.get(cat);
      cp.patterns.push(...profile.patterns);
      cp.severities.push(profile.severity);
      cp.rules.push(rule.name);
    }
  }

  _normalize(str) {
    if (!str) return '';
    let s = String(str);
    for (let i = 0; i < 3; i++) {
      try {
        const d = decodeURIComponent(s);
        if (d === s) break;
        s = d;
      } catch { break; }
    }
    return s.toLowerCase().normalize('NFKC');
  }

  _extractRequestFeatures(decodedReq) {
    const features = {
      url: this._normalize(decodedReq.url),
      path: this._normalize(decodedReq.path),
      method: (decodedReq.method || 'GET').toUpperCase(),
      query: this._normalize(JSON.stringify(decodedReq.query || {})),
      body: this._normalize(typeof decodedReq.body === 'string' ? decodedReq.body : JSON.stringify(decodedReq.body || {})),
      headers: this._normalize(JSON.stringify(decodedReq.headers || {})),
      cookies: this._normalize(JSON.stringify(decodedReq.cookies || {})),
      userAgent: (decodedReq.userAgent || '').toLowerCase(),
    };

    const rawFields = [
      decodedReq.url, decodedReq.body, JSON.stringify(decodedReq.query),
      JSON.stringify(decodedReq.headers), decodedReq.userAgent
    ].join(' ');
    const allFields = Object.values(features).join(' ');

    return {
      ...features,
      allFields,
      entropy: this._calculateEntropy(allFields),
      encodingLayers: this._countEncodingLayers(allFields),
      specialCharDensity: this._charClassRatio(allFields, /[^\w\s]/g),
      controlCharCount: (allFields.match(/[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]/g) || []).length,
      maxPatternSimilarity: 0,
      categoryMatches: new Map(),
    };
  }

  _calculateEntropy(str) {
    if (!str || str.length < 10) return 0;
    const freq = new Map();
    for (const char of str) {
      freq.set(char, (freq.get(char) || 0) + 1);
    }
    let entropy = 0;
    const len = str.length;
    for (const count of freq.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  _countEncodingLayers(str) {
    if (!str) return 0;
    let layers = 0;
    let current = str;
    for (let i = 0; i < 5; i++) {
      try {
        const d = decodeURIComponent(current);
        if (d === current) break;
        current = d;
        layers++;
      } catch {
        break;
      }
    }
    return layers;
  }

  _charClassRatio(str, regex) {
    if (!str || !str.length) return 0;
    const m = str.match(regex);
    return m ? m.length / str.length : 0;
  }

  _fuzzyPatternMatch(value, patternProfile) {
    if (!value || !patternProfile.compiled) return { matched: false, similarity: 0 };

    const str = String(value);
    const directMatch = patternProfile.compiled.test(str);

    let similarity = 0;
    const patternStr = patternProfile.pattern || '';

    if (patternStr.includes('|')) {
      const alternatives = patternStr.split('|').map(s => s.replace(/[()]/g, '').trim());
      for (const alt of alternatives) {
        if (alt.length > 3 && str.toLowerCase().includes(alt.toLowerCase())) {
          similarity = Math.max(similarity, 0.7);
        }
      }
    }

    if (patternStr.includes('select') || patternStr.includes('union')) {
      const sqlIndicators = ['select', 'union', 'from', 'where', 'insert', 'delete'];
      const found = sqlIndicators.filter(ind => str.toLowerCase().includes(ind));
      if (found.length >= 2) similarity = Math.max(similarity, 0.6);
    }

    if (patternStr.includes('script') || patternStr.includes('javascript')) {
      const xssIndicators = ['script', 'alert', 'onerror', 'onload', 'javascript', 'eval'];
      const found = xssIndicators.filter(ind => str.toLowerCase().includes(ind));
      if (found.length >= 1) similarity = Math.max(similarity, 0.5);
    }

    if (patternStr.includes('127.0.0.1') || patternStr.includes('localhost')) {
      const ssrfIndicators = ['localhost', '127.', '0.0.0.0', '169.254', 'metadata'];
      const found = ssrfIndicators.filter(ind => str.toLowerCase().includes(ind.toLowerCase()));
      if (found.length >= 1) similarity = Math.max(similarity, 0.8);
    }

    if (patternStr.includes('admin') || patternStr.includes('role')) {
      const massAssignIndicators = ['admin', 'role', 'permission', 'isadmin', 'is_root'];
      const found = massAssignIndicators.filter(ind => str.toLowerCase().includes(ind.toLowerCase()));
      if (found.length >= 1) similarity = Math.max(similarity, 0.75);
    }

    return { matched: directMatch, similarity: Math.min(similarity, 0.95) };
  }

  _calculateBehavioralScore(features, rawFields) {
    let score = 0;
    const indicators = [];
    const seen = new Map();

    const add = (weight, type, detail) => {
      const count = seen.get(type) || 0;
      const effective = weight / (1 + count * 0.7);
      seen.set(type, count + 1);
      score += effective;
      indicators.push({ type, weight: effective, detail });
    };

    if (features.entropy > 5.0 && features.specialCharDensity > 0.15) {
      add(3, 'high_entropy', `Entropy ${features.entropy.toFixed(2)} + special chars`);
    }

    if (features.encodingLayers > 2) {
      add(features.encodingLayers * 2, 'deep_encoding', `${features.encodingLayers} encoding layers`);
    }

    if (features.specialCharDensity > 0.3) {
      add(4, 'high_special_chars', `${(features.specialCharDensity * 100).toFixed(1)}% special chars`);
    }

    if (features.controlCharCount > 0) {
      add(features.controlCharCount * 3, 'control_chars', `${features.controlCharCount} control characters`);
    }

    if (/\x00/.test(rawFields)) {
      add(5, 'null_byte', 'Null byte detected - possible bypass attempt');
    }

    if (/[a-z][A-Z]|[A-Z][a-z]/.test(rawFields)) {
      add(3, 'mixed_casing', 'Mixed case obfuscation detected');
    }

    if (/%[0-9a-f]{2}/i.test(rawFields) && /\\x[0-9a-f]{2}/i.test(rawFields)) {
      add(4, 'mixed_encoding', 'Mixed URL and hex encoding');
    }

    if (/\.\.\/|\.\.\\/.test(features.allFields)) {
      add(5, 'path_traversal', 'Directory traversal patterns');
    }

    const nestingLevel = (rawFields.match(/[\{\[]/g) || []).length;
    if (nestingLevel > 15) {
      add(4, 'excessive_nesting', `High data structure nesting (${nestingLevel} levels)`);
    }

    return { score, indicators };
  }

  _calculateCategoryAnomaly(features) {
    const categoryScores = new Map();

    for (const [category, profile] of this.categoryProfiles) {
      let catScore = 0;
      const matchedPatterns = [];

      for (const pattern of profile.patterns) {
        for (const field of ['url', 'body', 'query', 'headers', 'cookies', 'userAgent']) {
          const result = this._fuzzyPatternMatch(features[field], pattern);
          if (result.matched) {
            catScore += 10;
            matchedPatterns.push({ pattern: pattern.name, field, type: 'direct' });
          } else if (result.similarity > 0.7) {
            catScore += result.similarity * 2;
            matchedPatterns.push({ pattern: pattern.name, field, type: 'fuzzy', similarity: result.similarity });
          }
        }
      }

      const criticalCount = profile.severities.filter(s => s === 'critical').length;
      const highCount = profile.severities.filter(s => s === 'high').length;
      catScore += Math.min(criticalCount, 2) + Math.min(highCount, 2) * 0.5;

      if (catScore > 0) {
        categoryScores.set(category, {
          score: catScore,
          severity: this._scoreToSeverity(catScore),
          matchedPatterns: matchedPatterns.slice(0, 5),
          ruleCount: profile.rules.length,
        });
      }
    }

    return categoryScores;
  }

  _scoreToSeverity(score) {
    if (score >= 25) return 'critical';
    if (score >= 15) return 'high';
    if (score >= 8) return 'medium';
    if (score >= 3) return 'low';
    return 'info';
  }

  _detectNovelAnomalies(features, categoryScores) {
    const novelIndicators = [];

    const totalCategoryScore = Array.from(categoryScores.values()).reduce((a, c) => a + c.score, 0);

    if (totalCategoryScore > 0 && totalCategoryScore < 5) {
      novelIndicators.push({
        type: 'fragmented_attack',
        detail: 'Partial indicators across multiple categories - possible evasion attempt',
        weight: 5,
      });
    }

    if (features.encodingLayers > 1 && totalCategoryScore > 10) {
      novelIndicators.push({
        type: 'encoded_attack',
        detail: 'Encoded payload with attack indicators - likely obfuscated exploit',
        weight: 8,
      });
    }

    const highEntropyCats = Array.from(categoryScores.entries())
      .filter(([_, data]) => data.matchedPatterns.some(p => p.type === 'fuzzy'));

    if (highEntropyCats.length >= 2) {
      novelIndicators.push({
        type: 'multi_vector_fuzzy',
        detail: `Fuzzy matches in ${highEntropyCats.length} categories - possible variant attack`,
        weight: 6,
      });
    }

    if (features.controlCharCount > 2 && features.specialCharDensity > 0.2) {
      const hasKnownCat = Array.from(categoryScores.keys()).some(c =>
        ['injection', 'xss', 'ssrf', 'traversal', 'command_injection'].includes(c)
      );
      if (!hasKnownCat) {
        novelIndicators.push({
          type: 'unknown_binary_payload',
          detail: 'Binary payload with control chars - possible novel exploit or protocol abuse',
          weight: 7,
        });
      }
    }

    return novelIndicators;
  }

  _updateHistory(ip, result) {
    const now = Date.now();
    if (!ANOMALY_HISTORY.has(ip)) {
      ANOMALY_HISTORY.set(ip, []);
    }
    const history = ANOMALY_HISTORY.get(ip);
    const cats = result.categoryScores ? Object.keys(result.categoryScores) : [];
    history.push({ timestamp: now, score: result.score, categories: cats });

    const cutoff = now - HISTORY_WINDOW;
    while (history.length > 0 && history[0].timestamp < cutoff) {
      history.shift();
    }
    if (history.length > MAX_HISTORY) {
      history.shift();
    }
  }

  _calculateTemporalAnomaly(ip, currentResult) {
    const history = ANOMALY_HISTORY.get(ip) || [];
    if (history.length < 3) return null;

    const recent = history.slice(-5);
    const avgScore = recent.reduce((a, h) => a + h.score, 0) / recent.length;
    const scoreSpike = currentResult.score > avgScore * 2;

    const allCats = new Set();
    recent.forEach(h => h.categories.forEach(c => allCats.add(c)));
    const currentCats = currentResult.categoryScores ? Object.keys(currentResult.categoryScores) : [];
    const newCats = currentCats.filter(c => !allCats.has(c));

    if (scoreSpike || newCats.length > 0) {
      return {
        type: 'behavioral_shift',
        detail: scoreSpike
          ? `Score spike: ${currentResult.score.toFixed(1)} vs avg ${avgScore.toFixed(1)}`
          : `New attack vectors: ${newCats.join(', ')}`,
        weight: scoreSpike ? 5 : 3,
      };
    }
    return null;
  }

  _detectCrossFieldCorrelation(features) {
    const signals = [];
    const all = features.allFields;

    if (features.query?.includes('select') && features.body?.includes('from')) {
      signals.push({ type: 'distributed_sqli', weight: 6, detail: 'SELECT in query + FROM in body' });
    }

    if (features.url?.includes('union') && features.body?.includes('select')) {
      signals.push({ type: 'fragmented_union', weight: 5, detail: 'UNION/SELECT split across fields' });
    }

    if (all.includes('script') && (all.includes('onerror') || all.includes('onload'))) {
      signals.push({ type: 'xss_correlation', weight: 4, detail: 'Script tag + event handler' });
    }

    if (features.entropy > 5.0 && features.encodingLayers >= 2) {
      signals.push({ type: 'encoded_payload', weight: 6, detail: 'High entropy with deep encoding' });
    }

    const blindPatterns = /(sleep\s*\(|pg_sleep\s*\(|waitfor\s+delay|benchmark\s*\()/i;
    if (blindPatterns.test(all)) {
      signals.push({ type: 'blind_sqli_indicators', weight: 8, detail: 'Time-based blind attack functions detected (sleep/waitfor/benchmark)'});
    }

    return signals;
  }

  analyze(decodedReq) {
    const features = this._extractRequestFeatures(decodedReq);
    const rawFields = [
      decodedReq.url, decodedReq.body, JSON.stringify(decodedReq.query),
      JSON.stringify(decodedReq.headers), decodedReq.userAgent
    ].join(' ');
    const behavioral = this._calculateBehavioralScore(features, rawFields);
    const categoryScores = this._calculateCategoryAnomaly(features);
    const correlationSignals = this._detectCrossFieldCorrelation(features);
    const novelIndicators = this._detectNovelAnomalies(features, categoryScores);

    let totalScore = behavioral.score;
    const allIndicators = [...behavioral.indicators];

    for (const [category, data] of categoryScores) {
      totalScore += data.score;
      allIndicators.push({
        type: `${category}_anomaly`,
        weight: data.score,
        detail: `${category}: ${data.matchedPatterns.length} patterns, severity ${data.severity}`,
      });
    }

    for (const ind of novelIndicators) {
      totalScore += ind.weight;
      allIndicators.push(ind);
    }

    for (const sig of correlationSignals) {
      totalScore += sig.weight;
      allIndicators.push(sig);
    }

    const confidence = Math.min(1, totalScore / 40);

    const result = {
      score: totalScore,
      severity: this._scoreToSeverity(totalScore),
      behavioral,
      categoryScores: Object.fromEntries(categoryScores),
      novelIndicators,
      features: {
        entropy: features.entropy,
        encodingLayers: features.encodingLayers,
        specialCharDensity: features.specialCharDensity,
        controlCharCount: features.controlCharCount,
      },
    };

    const temporal = this._calculateTemporalAnomaly(decodedReq.ip, result);
    if (temporal) {
      result.temporalAnomaly = temporal;
      result.score += temporal.weight;
      allIndicators.push(temporal);
    }

    this._updateHistory(decodedReq.ip, result);

    if (result.score < 25) {
      return { detected: false, score: result.score, level: 'none', confidence: 0 };
    }

    const topCategories = Array.from(categoryScores.entries())
      .sort((a, b) => b[1].score - a[1].score)
      .slice(0, 3)
      .map(([cat, data]) => `${cat}(${data.severity})`);

    const topSignals = allIndicators.sort((a, b) => b.weight - a.weight).slice(0, 3).map(i => i.type);

    return {
      detected: true,
      rule: 'smart_anomaly_detection',
      tags: ['anomaly', 'heuristic', 'ai-like', ...topCategories],
      severity: result.severity,
      category: topCategories[0]?.split('(')[0] || 'unknown',
      description: `Score ${result.score.toFixed(1)} (${result.severity}) | signals: ${topSignals.join(', ')}`,
      author: 'laraxaar',
      score: result.score,
      confidence,
      explanation: {
        summary: this._generateDescription(result, allIndicators),
        reasons: allIndicators.sort((a, b) => b.weight - a.weight).slice(0, 5),
        matchedCategories: Object.keys(result.categoryScores),
        correlationSignals: correlationSignals.map(s => s.type),
      },
      analysis: {
        score: result.score,
        severity: result.severity,
        confidence,
        behavioralScore: behavioral.score,
        categoryMatches: result.categoryScores,
        novelIndicators: novelIndicators.map(i => i.type),
        correlationSignals: correlationSignals.map(s => s.type),
        topIndicators: allIndicators.sort((a, b) => b.weight - a.weight).slice(0, 5),
        temporalAnomaly: result.temporalAnomaly,
        features: {
          entropy: features.entropy,
          encodingLayers: features.encodingLayers,
          specialCharDensity: features.specialCharDensity,
        },
      },
      matchedPatterns: allIndicators.slice(0, 5).map(i => ({
        name: i.type,
        matched: i.detail,
      })),
    };
  }

  _generateDescription(result, indicators) {
    const parts = [];
    parts.push(`Smart anomaly score ${result.score.toFixed(1)} (${result.severity})`);

    const topCats = Object.entries(result.categoryScores || {})
      .sort((a, b) => b[1].score - a[1].score)
      .slice(0, 2);

    if (topCats.length > 0) {
      parts.push(`Categories: ${topCats.map(([c]) => c).join(', ')}`);
    }

    if (result.novelIndicators?.length > 0) {
      parts.push(`Novel: ${result.novelIndicators.map(i => i.type).join(', ')}`);
    }

    const topInd = indicators.sort((a, b) => b.weight - a.weight)[0];
    if (topInd) {
      parts.push(`Primary: ${topInd.type}`);
    }

    return parts.join(' | ');
  }
}

const detector = new SmartAnomalyDetector();

function check(decodedReq) {
  const result = detector.analyze(decodedReq);
  if (result.detected) {
    return [result];
  }
  return [];
}

module.exports = { check, SmartAnomalyDetector };

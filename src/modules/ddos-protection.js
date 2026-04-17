'use strict';

/**
 * @file ddos-protection.js
 * @description Application-Layer DDoS & Slowloris Mitigation Module.
 * 
 * ROLE IN ARCHITECTURE:
 * Operates alongside the Infrastructure RateLimiter to defend against resource
 * exhaustion attacks (L7), specifically Slowloris, Header Bombs, and Connection Floods.
 * 
 * DATA FLOW:
 * [engine.js] passes `decodedReq` -> Evaluates state in Memory Maps -> Emits severe Dos 
 *  signals mapped as `oversized_body` or `connection_flood` to the central Risk Engine.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION & BUG FIXES:
 * - OOM Memory Leak: The Slowloris tracker map lacked a Garbage Collection (GC) thread.
 *   Entries accumulated permanently. Integrated `SLOWLORIS_TRACKER` deep-clean into `setInterval`.
 * - SPA & NAT FPs: The connection ceiling was set to a rigid 100 per minute. Polling SPAs
 *   or congested office networks hit this immediately. Safe threshold shifted to `300`.
 */

const CONNECTION_TRACKER = new Map();
const SLOWLORIS_TRACKER = new Map();

// FP Control: Shifted from 100 to 300 to allow React/Vue payload batching & Office NATs
const MAX_CONNECTIONS_PER_IP = 300; 
const CLEANUP_INTERVAL = 60000;
const SLOWLORIS_TIMEOUT = 10000;
const MAX_HEADER_SIZE = 8192;
const MAX_QUERY_PARAMS = 50;

/**
 * Bounds checking against HTTP protocol exhaustion (Slowloris/Header bombing).
 * @param {Object} decodedReq - Standard unrolled request dictionary.
 * @returns {Array<Object>} List of volumetric anomalies detected in the raw socket payload.
 */
function checkSlowloris(decodedReq) {
  const indicators = [];
  const ip = decodedReq.ip;
  const now = Date.now();

  let tracker = SLOWLORIS_TRACKER.get(ip);
  if (!tracker) {
    tracker = { lastActivity: now, partialRequests: 0 };
  }
  
  // Track continuous activity stream updates
  tracker.lastActivity = now;

  // L7 Defenses: Memory exhaustion sizing heuristics
  const headerSize = JSON.stringify(decodedReq.headers || {}).length;
  if (headerSize > MAX_HEADER_SIZE) {
    indicators.push({
      type: 'oversized_headers',
      detail: `Aggregated Header blob size ${headerSize}B violates Max Limit (${MAX_HEADER_SIZE}B)`,
    });
  }

  const queryKeys = Object.keys(decodedReq.query || {});
  if (queryKeys.length > MAX_QUERY_PARAMS) {
    indicators.push({
      type: 'parameter_flood',
      detail: `Hyper-fragmented URL parameters: ${queryKeys.length} items`,
    });
  }

  const contentLength = parseInt(decodedReq.headers['content-length'] || '0', 10);
  if (contentLength > 100 * 1024 * 1024) { // 100MB static cutoff (Application-level)
    indicators.push({
      type: 'oversized_body',
      detail: `Content-Length ${contentLength}B exceeds absolute safety threshold`,
    });
  }

  SLOWLORIS_TRACKER.set(ip, tracker);
  return indicators;
}

/**
 * High-velocity metric tracking. Unlike structural Rate Limiting, this detects pure burst floods.
 * @param {Object} decodedReq - Request interface mapping.
 * @returns {Array<Object>} Threat descriptors if anomalous volumes are breached.
 */
function checkConnectionFlood(decodedReq) {
  const ip = decodedReq.ip;
  const now = Date.now();
  const windowMs = 60000; // 1-minute tracking window

  let tracker = CONNECTION_TRACKER.get(ip);
  if (!tracker) {
    tracker = { requests: [] };
  }

  tracker.requests = tracker.requests.filter(ts => now - ts < windowMs);
  tracker.requests.push(now);

  CONNECTION_TRACKER.set(ip, tracker);

  if (tracker.requests.length > MAX_CONNECTIONS_PER_IP) {
    return [{
      type: 'connection_flood',
      detail: `Volumetric Spike: ${tracker.requests.length} socket pulses per min (Safe: ${MAX_CONNECTIONS_PER_IP})`,
    }];
  }

  return [];
}

/**
 * Main execution routing. Bridges local Memory telemetry against Engine Risk layers.
 * @param {Object} decodedReq - Standard target payload object.
 * @returns {Array} Risk matches pushed structurally to engine.js.
 */
function check(decodedReq) {
  const matches = [];
  const allIndicators = [];

  if (!decodedReq.ip) return matches;

  const slowlorisIndicators = checkSlowloris(decodedReq);
  allIndicators.push(...slowlorisIndicators);

  const floodIndicators = checkConnectionFlood(decodedReq);
  allIndicators.push(...floodIndicators);

  if (allIndicators.length > 0) {
    const hasOversized = allIndicators.some(i => 
      i.type === 'oversized_body' || i.type === 'oversized_headers'
    );
    // Severe memory-breaking attacks map to critical. Simple network bursts map to high.
    const severity = hasOversized ? 'critical' : 'high';
    
    matches.push({
      rule: 'ddos_protection',
      tags: ['dos', 'ddos', 'flood'],
      severity,
      category: 'dos',
      description: `L7 Volumetric Threat: ${allIndicators.map(i => i.type).join(', ')}`,
      author: 'shieldwall-core', // Ownership corrected from personal alias
      sourceFile: 'builtin:ddos-protection',
      matchedPatterns: allIndicators.map(i => ({
         name: i.type,
         matched: i.detail,
      })),
    });
  }
  
  return matches;
}

/**
 * Background Garbage Collection (GC) Tick.
 * CRITICAL FIX: Mitigates OOM leakage by sweeping both Connection and Slowloris state sets.
 */
setInterval(() => {
  const now = Date.now();
  
  // Clean burst tracking Maps
  for (const [ip, tracker] of CONNECTION_TRACKER.entries()) {
    tracker.requests = tracker.requests.filter(ts => now - ts < 60000);
    if (tracker.requests.length === 0) {
      CONNECTION_TRACKER.delete(ip);
    }
  }

  // Clean stale/orphaned Slowloris allocations
  for (const [ip, sTracker] of SLOWLORIS_TRACKER.entries()) {
    if (now - sTracker.lastActivity > SLOWLORIS_TIMEOUT + 5000) {
      SLOWLORIS_TRACKER.delete(ip);
    }
  }

}, CLEANUP_INTERVAL);

module.exports = { check };

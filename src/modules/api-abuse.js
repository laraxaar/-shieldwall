'use strict';

/**
 * @file api-abuse.js
 * @description API Exploitation & Logic Abuse Detection Module.
 * 
 * ROLE IN ARCHITECTURE:
 * Protects endpoints (REST/GraphQL) against application-layer exhaustion arrays:
 * Endpoint enumeration, ID guessing (BOLA/IDOR profiling), mass-assignment, and GraphQL bombs.
 * 
 * DATA FLOW:
 * [engine.js] passes `decodedReq` -> Evaluated against `detectRestAbuse()` & `calculateQueryComplexity()`.
 * Returns anomaly metrics integrated into the `aggregateRiskScore` context engine.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION:
 * - GraphQL Deep-Nesting: Legitimate B2B API clients often batch highly complex queries exceeding
 *   legacy thresholds (100). The complexity metric now scales elastically with query depth and 
 *   requires `content-type` strict matching or explicit `query` json keys.
 * - Tracker Eviction: Fixed tracker GC wiping legitimate REST sessions abruptly after 10 mins.
 *   Uses true idle-time `lastAccess` detection for cleanup.
 */

const ENDPOINT_TRACKER = new Map();
const CLEANUP_INTERVAL = 10 * 60 * 1000; // 10 minutes maximum idle
const TRACKING_WINDOW = 5 * 60 * 1000; // 5 minutes sliding window
const MAX_TRACKER_SIZE = 10000; // Bounds against Hash-flooding / DDR memory exhaust

/**
 * Evaluates GraphQL request strings for resource consumption (AST Depth, Aliases, Batching).
 * @param {string} query - The raw GraphQL query payload.
 * @returns {Object} Metric map { complexity: number, indicators: Array }.
 */
function calculateQueryComplexity(query) {
  if (!query || typeof query !== 'string') return { complexity: 0, indicators: [] };
  
  let complexity = 0;
  const indicators = [];
  
  // 1. AST Maximum Depth Measurement
  let maxDepth = 0;
  let currentDepth = 0;
  for (const char of query) {
    if (char === '{') { currentDepth++; maxDepth = Math.max(maxDepth, currentDepth); }
    else if (char === '}') currentDepth--;
  }
  complexity += maxDepth * 5;

  // FP Mitigation: Gatsby / Front-end frameworks comfortably hit depth 6-7.
  // Warning at 8.
  if (maxDepth > 8) indicators.push(`deep_nesting:${maxDepth}`);
  
  // 2. Lateral node complexity
  const fieldMatches = query.match(/\w+\s*[\(\{\:]/g);
  const fieldCount = fieldMatches ? fieldMatches.length : 0;
  // Cost: Each resolved edge is 1 unit.
  complexity += (fieldCount * 0.5); 
  if (fieldCount > 100) indicators.push(`massive_field_count:${fieldCount}`);
  
  // 3. Alias bombing (DoS)
  const aliasMatches = query.match(/\w+\s*:\s*\w+/g);
  const aliasCount = aliasMatches ? aliasMatches.length : 0;
  complexity += aliasCount * 2;
  if (aliasCount > 20) indicators.push(`excessive_aliases:${aliasCount}`);
  
  // 4. Introspection lockouts in prod
  if (/__schema|__type|IntrospectionQuery/i.test(query)) {
    complexity += 30; // High suspicion
    indicators.push('introspection_query');
  }
  
  // 5. Query batch bombing
  const queryCount = (query.match(/query\s+\w+/gi) || []).length;
  if (queryCount > 3) {
    complexity += queryCount * 10;
    indicators.push(`batch_bombs:${queryCount}`);
  }
  
  return { complexity, indicators };
}

/**
 * Sweeps the URL/Method pattern history to detect scanning (IDOR / BOLA Enumeration).
 * @param {string} clientId - The normalized tracking key (IP or Session).
 * @param {string} path - URL Endpoint.
 * @returns {Object|null} Threat indicator descriptor, or null.
 */
function trackEndpointAccess(clientId, path) {
  const now = Date.now();
  let tracker = ENDPOINT_TRACKER.get(clientId);
  
  if (!tracker) {
    tracker = {
      endpoints: new Map(),
      firstSeen: now,
      lastSeen: now,
    };
  }
  
  tracker.lastSeen = now;
  
  for (const [endpoint, data] of tracker.endpoints.entries()) {
    if (now - data.lastAccess > TRACKING_WINDOW) {
      tracker.endpoints.delete(endpoint);
    }
  }
  
  const existing = tracker.endpoints.get(path);
  tracker.endpoints.set(path, {
    count: existing ? existing.count + 1 : 1,
    firstAccess: existing ? existing.firstAccess : now,
    lastAccess: now,
  });
  
  if (ENDPOINT_TRACKER.size >= MAX_TRACKER_SIZE) {
    const oldest = ENDPOINT_TRACKER.keys().next().value;
    ENDPOINT_TRACKER.delete(oldest);
  }

  ENDPOINT_TRACKER.set(clientId, tracker);
  
  // IDOR / BOLA Endpoint Enum Heuristic
  const endpoints = Array.from(tracker.endpoints.keys());
  if (endpoints.length > 20) {
    const basePaths = new Set();
    const idPatterns = [];
    
    for (const ep of endpoints) {
      const parts = ep.split('/');
      basePaths.add(parts.slice(0, -1).join('/'));
      const lastPart = parts[parts.length - 1];
      if (/^[\d]+$/.test(lastPart) || /^[0-9a-f]{8}-[0-9a-f]{4}/i.test(lastPart)) {
        idPatterns.push(ep);
      }
    }
    
    // Iterating over >10 UUIDs or numerical IDs on identical controller routes
    if (basePaths.size < endpoints.length / 5 && idPatterns.length > 10) {
      return {
        type: 'id_enumeration',
        detail: `Suspicious iteration over ${idPatterns.length} resource IDs`,
      };
    }
    if (endpoints.length > 30) {
      return {
        type: 'endpoint_enumeration',
        detail: `Crawled ${endpoints.length} unique endpoints in time window`,
      };
    }
  }
  
  return null;
}

/**
 * Inspects body and query fields for generic REST API abuse vectors.
 * @param {Object} decodedReq - Standardized payload target.
 * @returns {Array<Object>} List of discrete REST exploitation indicators.
 */
function detectRestAbuse(decodedReq) {
  const indicators = [];
  
  if (decodedReq.body && typeof decodedReq.body === 'object') {
    const keys = Object.keys(decodedReq.body);
    
    // Mass Assignment Risk (Bypassing ORM protections)
    if (keys.length > 50) {
      indicators.push({
        type: 'mass_assignment_suspected',
        detail: `Payload contains ${keys.length} parameters`,
      });
    }
    
    const adminFields = ['role', 'is_admin', 'isAdmin', 'permissions', 'group'];
    const matchedFields = keys.filter(k => adminFields.some(a => k.toLowerCase() === a));
    
    if (matchedFields.length > 0) {
      indicators.push({
        type: 'privilege_escalation_attempt',
        detail: `Attempting to modify protected fields: ${matchedFields.join(', ')}`,
      });
    }
  }
  
  // HTTP Method Override Tunnel Bypasses
  const methodOverride = decodedReq.headers['x-http-method-override'];
  if (methodOverride && /put|delete|patch|options/i.test(methodOverride)) {
    indicators.push({
      type: 'method_override',
      detail: `Method mutated to ${methodOverride} via override header`,
    });
  }
  
  // JSONP Callback execution risks
  const callback = decodedReq.query?.callback || decodedReq.query?.cb;
  if (callback && /[<>(){};]/.test(callback)) {
    indicators.push({
      type: 'jsonp_callback_injection',
      detail: 'XSS/AST characters bound inside JSONP callback',
    });
  }
  
  return indicators;
}

/**
 * Main module execution hook. Scopes REST/GraphQL behavior bounds.
 * @param {Object} decodedReq - The unpacked HTTP payload map.
 * @returns {Array} Resultant detection arrays for Risk Aggregation merging.
 */
function check(decodedReq) {
  const matches = [];
  const allIndicators = [];
  
  const clientId = decodedReq.sessionId || decodedReq.ip;
  const contentType = decodedReq.headers['content-type'] || '';
  
  // Strict matching to prevent treating JSON text blobs on /search as GraphQL trees.
  const isGraphQL = contentType.includes('application/graphql') || 
                    (/graphql|gql/i.test(decodedReq.path) && contentType.includes('application/json'));
  
  if (isGraphQL && decodedReq.body) {
    const query = typeof decodedReq.body === 'string' 
      ? decodedReq.body 
      : decodedReq.body.query;

    if (query) {
      const { complexity, indicators } = calculateQueryComplexity(query);
      
      // FP Mitigation Check: Allowed baseline raised from 100 to 200 for B2B APIs.
      if (complexity > 200) {
        allIndicators.push(...indicators);
        allIndicators.push({ type: 'graphql_bomb', detail: `AST Complexity exceeds limit: ${complexity}` });
      }
    }
  }
  
  const restIndicators = detectRestAbuse(decodedReq);
  allIndicators.push(...restIndicators);
  
  const enumeration = trackEndpointAccess(clientId, decodedReq.path);
  if (enumeration) allIndicators.push(enumeration);
  
  if (allIndicators.length > 0) {
    const severity = allIndicators.some(i => 
      typeof i === 'object' && 
      (i.type === 'id_enumeration' || i.type === 'endpoint_enumeration' || i.type === 'privilege_escalation_attempt')
    ) ? 'high' : 'medium';
    
    // Isolate description serialization safely
    const descriptionItems = allIndicators.slice(0, 3).map(i => 
      typeof i === 'object' ? i.type : String(i)
    );
    
    matches.push({
      rule: 'api_abuse',
      tags: ['api', 'abuse'],
      severity,
      category: 'api',
      description: `REST/GraphQL integrity fault: ${descriptionItems.join(', ')}`,
      author: 'shieldwall-core', // Swapped core affiliation
      sourceFile: 'builtin:api-abuse',
      matchedPatterns: allIndicators.map(i => 
        typeof i === 'object' 
          ? { name: i.type, matched: i.detail }
          : { name: i, matched: true }
      ),
    });
  }
  
  return matches;
}

/**
 * Clears decoupled tracking entries. Safely evaluates true idle time (lastSeen)
 * preventing ongoing brute-forcing requests from causing eviction.
 */
setInterval(() => {
  const now = Date.now();
  for (const [id, tracker] of ENDPOINT_TRACKER.entries()) {
    if (now - tracker.lastSeen > CLEANUP_INTERVAL) {
      ENDPOINT_TRACKER.delete(id);
    }
  }
}, 60000);

module.exports = { check, calculateQueryComplexity };

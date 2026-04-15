'use strict';

// API abuse detection — identifies GraphQL/REST API abuse patterns
// Query complexity, batch attacks, endpoint enumeration

const ENDPOINT_TRACKER = new Map();
const CLEANUP_INTERVAL = 10 * 60 * 1000; // 10 minutes
const TRACKING_WINDOW = 5 * 60 * 1000; // 5 minutes
const MAX_TRACKER_SIZE = 10000; // Prevent memory exhaustion during DDoS

function calculateQueryComplexity(query) {
  if (!query) return 0;
  
  let complexity = 0;
  const indicators = [];
  
 
  let maxDepth = 0;
  let currentDepth = 0;
  for (const char of query) {
    if (char === '{') { currentDepth++; maxDepth = Math.max(maxDepth, currentDepth); }
    else if (char === '}') currentDepth--;
  }
  complexity += maxDepth * 5;
  if (maxDepth > 4) indicators.push(`deep_nesting:${maxDepth}`);
  
  
  const fieldMatches = query.match(/\w+\s*[\(\{\:]/g);
  const fieldCount = fieldMatches ? fieldMatches.length : 0;
  complexity += fieldCount;
  if (fieldCount > 50) indicators.push(`many_fields:${fieldCount}`);
  
  
  const aliasMatches = query.match(/\w+\s*:\s*\w+/g);
  const aliasCount = aliasMatches ? aliasMatches.length : 0;
  complexity += aliasCount * 2;
  if (aliasCount > 10) indicators.push(`many_aliases:${aliasCount}`);
  
 
  if (/__schema|__type|IntrospectionQuery/i.test(query)) {
    complexity += 20;
    indicators.push('introspection_query');
  }
  
 
  const queryCount = (query.match(/query\s+\w+/gi) || []).length;
  if (queryCount > 1) {
    complexity += queryCount * 10;
    indicators.push(`batch_queries:${queryCount}`);
  }
  
  return { complexity, indicators };
}

function trackEndpointAccess(clientId, path) {
  const now = Date.now();
  let tracker = ENDPOINT_TRACKER.get(clientId);
  
  if (!tracker) {
    tracker = {
      endpoints: new Map(),
      firstSeen: now,
    };
  }
  
  
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
  
  // Prevent memory exhaustion - evict oldest if at capacity
  if (ENDPOINT_TRACKER.size >= MAX_TRACKER_SIZE) {
    const oldest = ENDPOINT_TRACKER.keys().next().value;
    ENDPOINT_TRACKER.delete(oldest);
  }

  ENDPOINT_TRACKER.set(clientId, tracker);
  
  
  const uniqueEndpoints = tracker.endpoints.size;
  const accessWindow = now - tracker.firstSeen;
  
  
  if (uniqueEndpoints > 20 && accessWindow < 60000) {
    return {
      type: 'endpoint_enumeration',
      detail: `${uniqueEndpoints} unique endpoints accessed in ${(accessWindow/1000).toFixed(0)}s`,
    };
  }
  
  
  const numericPaths = Array.from(tracker.endpoints.keys())
    .filter(p => /\/\d+\/?$/.test(p))
    .map(p => parseInt(p.match(/\/(\d+)\/?$/)[1]));
  
  if (numericPaths.length >= 5) {
    const sorted = [...numericPaths].sort((a, b) => a - b);
    let sequentialCount = 0;
    for (let i = 1; i < sorted.length; i++) {
      if (sorted[i] === sorted[i-1] + 1) sequentialCount++;
    }
    
    if (sequentialCount >= 3) {
      return {
        type: 'id_enumeration',
        detail: `Sequential ID access detected (${sequentialCount + 1} IDs)`,
      };
    }
  }
  
  return null;
}

function detectRestAbuse(decodedReq) {
  const indicators = [];
  const path = decodedReq.path || '';
  const body = decodedReq.body || '';
  
  
  if (typeof body === 'object' && body !== null) {
    const sensitiveFields = ['id', 'admin', 'role', 'password', 'isAdmin', 'is_admin'];
    for (const field of sensitiveFields) {
      if (body[field] !== undefined) {
        indicators.push({
          type: 'mass_assignment_attempt',
          detail: `Sensitive field "${field}" in request body`,
        });
      }
    }
  }
  
  
  const methodOverride = decodedReq.headers['x-http-method-override'];
  if (methodOverride && /put|delete|patch/i.test(methodOverride)) {
    indicators.push({
      type: 'method_override',
      detail: `Method override to ${methodOverride} via header`,
    });
  }
  
  
  const callback = decodedReq.query?.callback || decodedReq.query?.cb;
  if (callback && /[<>(){};]/.test(callback)) {
    indicators.push({
      type: 'jsonp_callback_injection',
      detail: 'Suspicious characters in JSONP callback',
    });
  }
  
  return indicators;
}

function check(decodedReq) {
  const matches = [];
  const allIndicators = [];
  
  const clientId = decodedReq.sessionId || decodedReq.ip;
  const contentType = decodedReq.headers['content-type'] || '';
  const isGraphQL = contentType.includes('application/graphql') || 
                    /graphql/i.test(decodedReq.path);
  
  if (isGraphQL && decodedReq.body) {
    const query = typeof decodedReq.body === 'string' 
      ? decodedReq.body 
      : decodedReq.body.query;
    
    if (query) {
      const { complexity, indicators } = calculateQueryComplexity(query);
      
      if (complexity > 100) {
        allIndicators.push(...indicators);
        allIndicators.push(`complexity_score:${complexity}`);
      }
    }
  }
  
  const restIndicators = detectRestAbuse(decodedReq);
  allIndicators.push(...restIndicators);
  
  const enumeration = trackEndpointAccess(clientId, decodedReq.path);
  if (enumeration) {
    allIndicators.push(enumeration);
  }
  
  if (allIndicators.length > 0) {
    const severity = allIndicators.some(i => 
      typeof i === 'object' && 
      (i.type === 'id_enumeration' || i.type === 'endpoint_enumeration')
    ) ? 'high' : 'medium';
    
    const descriptionItems = allIndicators.slice(0, 3).map(i => 
      typeof i === 'object' ? i.type : i
    );
    
    matches.push({
      rule: 'api_abuse',
      tags: ['api', 'abuse'],
      severity,
      category: 'api',
      description: `API abuse: ${descriptionItems.join(', ')}`,
      author: 'laraxaar',
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


setInterval(() => {
  const now = Date.now();
  for (const [id, tracker] of ENDPOINT_TRACKER.entries()) {
    if (now - tracker.firstSeen > CLEANUP_INTERVAL) {
      ENDPOINT_TRACKER.delete(id);
    }
  }
}, CLEANUP_INTERVAL);

module.exports = { check, calculateQueryComplexity };

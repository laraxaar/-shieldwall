'use strict';

const CONNECTION_TRACKER = new Map();
const SLOWLORIS_TRACKER = new Map();
const MAX_CONNECTIONS_PER_IP = 100;
const CLEANUP_INTERVAL = 60000;
const SLOWLORIS_TIMEOUT = 10000;
const MAX_HEADER_SIZE = 8192;
const MAX_QUERY_PARAMS = 50;

function checkSlowloris(decodedReq) {
  const indicators = [];
  const ip = decodedReq.ip;
  const now = Date.now();

  let tracker = SLOWLORIS_TRACKER.get(ip);
  if (!tracker) {
    tracker = { lastActivity: now, partialRequests: 0 };
  }

  const headerSize = JSON.stringify(decodedReq.headers).length;
  if (headerSize > MAX_HEADER_SIZE) {
    indicators.push({
      type: 'oversized_headers',
      detail: `Header size ${headerSize} bytes exceeds ${MAX_HEADER_SIZE}`,
    });
  }

  const queryKeys = Object.keys(decodedReq.query || {});
  if (queryKeys.length > MAX_QUERY_PARAMS) {
    indicators.push({
      type: 'parameter_flood',
      detail: `${queryKeys.length} query parameters (max ${MAX_QUERY_PARAMS})`,
    });
  }

  const contentLength = parseInt(decodedReq.headers['content-length'] || '0', 10);
  if (contentLength > 100 * 1024 * 1024) {
    indicators.push({
      type: 'oversized_body',
      detail: `Content-Length ${contentLength} bytes exceeds limit`,
    });
  }

  SLOWLORIS_TRACKER.set(ip, tracker);

  if (now - tracker.lastActivity > SLOWLORIS_TIMEOUT) {
    SLOWLORIS_TRACKER.delete(ip);
  }

  return indicators;
}

function checkConnectionFlood(decodedReq) {
  const ip = decodedReq.ip;
  const now = Date.now();
  const windowMs = 60000;

  let tracker = CONNECTION_TRACKER.get(ip);
  if (!tracker) {
    tracker = { requests: [], blocked: false };
  }

  tracker.requests = tracker.requests.filter(ts => now - ts < windowMs);
  tracker.requests.push(now);

  CONNECTION_TRACKER.set(ip, tracker);

  if (tracker.requests.length > MAX_CONNECTIONS_PER_IP) {
    return [{
      type: 'connection_flood',
      detail: `${tracker.requests.length} connections in 1 minute (max ${MAX_CONNECTIONS_PER_IP})`,
    }];
  }

  return [];
}

function check(decodedReq) {
  const matches = [];
  const allIndicators = [];

  const slowlorisIndicators = checkSlowloris(decodedReq);
  allIndicators.push(...slowlorisIndicators);

  const floodIndicators = checkConnectionFlood(decodedReq);
  allIndicators.push(...floodIndicators);

  if (allIndicators.length > 0) {
    const hasOversized = allIndicators.some(i => 
      i.type === 'oversized_body' || i.type === 'oversized_headers'
    );
    const severity = hasOversized ? 'critical' : 'high';
    
    matches.push({
      rule: 'ddos_protection',
      tags: ['dos', 'ddos', 'flood'],
      severity,
      category: 'dos',
      description: `DDoS indicators: ${allIndicators.map(i => i.type).join(', ')}`,
      author: 'laraxaar',
      sourceFile: 'builtin:ddos-protection',
      matchedPatterns: allIndicators.map(i => ({
        name: i.type,
        matched: i.detail,
      })),
    });
  }
  
  return matches;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, tracker] of CONNECTION_TRACKER.entries()) {
    tracker.requests = tracker.requests.filter(ts => now - ts < 60000);
    if (tracker.requests.length === 0) {
      CONNECTION_TRACKER.delete(ip);
    }
  }
}, CLEANUP_INTERVAL);

module.exports = { check };

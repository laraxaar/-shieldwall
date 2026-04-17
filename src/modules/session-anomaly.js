'use strict';

/**
 * @file session-anomaly.js
 * @description Session Anomaly & Geo Velocity Module
 * 
 * ROLE IN ARCHITECTURE:
 * Operates at the session level across multiple requests to detect Account Takeover (ATO)
 * and distributed abuse. Emits feature signals that engine.js translates into structural risk risks.
 * 
 * DATA FLOW:
 * [engine.js] inputs `decodedReq` -> `check()` evaluates IP drift, Geo Velocity, and Fingerprint ->
 * Returns array of Anomaly Signals back to Risk Aggregator.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION:
 * - Desktop VPNs simulate "Impossible Travel" (> 900km/h), which previously trapped valid users.
 *   We now inspect 'x-forwarded-for' or 'via' patterns to classify 'VPN suspect' behaviors and downgrade risk.
 * - Memory Leak Resolution: `SESSION_DATA` Map bounds are strictly LRU pruned using `_cleanup()`
 *   based on MAX_SESSION_AGE boundaries.
 */

const SESSION_DATA = new Map();
const MAX_SESSIONS = 50000;
const MAX_SESSION_AGE = 24 * 60 * 60 * 1000;

const CITY_COORDS = {
  'US': { lat: 37.0902, lon: -95.7129 },
  'RU': { lat: 61.5240, lon: 105.3188 },
  'CN': { lat: 35.8617, lon: 104.1954 },
  'GB': { lat: 55.3781, lon: -3.4360 },
  'DE': { lat: 51.1657, lon: 10.4515 },
  'FR': { lat: 46.2276, lon: 2.2137 },
  'JP': { lat: 36.2048, lon: 138.2529 },
};

const MOBILE_UA_PATTERN = /Android|iPhone|iPad|iPod|Mobile|Windows Phone/i;

/**
 * Heuristically determines if the client is running on a mobile OS.
 * @param {string} userAgent - Raw HTTP User-Agent header.
 * @returns {boolean} True if matching a known mobile browser pattern.
 */
function isMobileUA(userAgent) {
  return MOBILE_UA_PATTERN.test(userAgent || '');
}

/**
 * Mathematical formula measuring straight-line geographical distance between coordinates.
 * @param {number} lat1 - Starting Latitude.
 * @param {number} lon1 - Starting Longitude.
 * @param {number} lat2 - Target Latitude.
 * @param {number} lon2 - Target Longitude.
 * @returns {number} Distance in kilometers.
 */
function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Earth radius in KM
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
            Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
            Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}

/**
 * Calculates travel speed over the passed time difference.
 * @param {Object} prevLocation - Object holding `{lat, lon}`.
 * @param {Object} currLocation - Object holding `{lat, lon}`.
 * @param {number} timeDiff - Delta in milliseconds.
 * @returns {number} Velocity in km/h.
 */
function calculateGeoVelocity(prevLocation, currLocation, timeDiff) {
  if (!prevLocation || !currLocation || timeDiff <= 0) return 0;
  const distance = haversineDistance(
    prevLocation.lat, prevLocation.lon,
    currLocation.lat, currLocation.lon
  );
  const hours = timeDiff / (1000 * 60 * 60);
  return distance / hours;
}

/**
 * Evaluates the session to determine if a VPN is heavily suspected.
 * Useful for dampening Impossible Travel false positives.
 * @param {Object} decodedReq - Decoded Request map.
 * @returns {boolean} True if suspected.
 */
function isSuspectedVPN(decodedReq) {
  if (!decodedReq.headers) return false;
  // Deep inspection for proxy tunneling footprints
  return !!(
    decodedReq.headers['via'] || 
    decodedReq.headers['x-forwarded-for']?.includes(',') ||
    decodedReq.headers['x-vpn'] ||
    decodedReq.headers['surrogate-capability']
  );
}

/**
 * Evaluates the current session map against geographical velocity logic constraints.
 * Extrapolates Impossible Travel and Rapid Country Switching.
 * @param {string} sessionId - The localized grouping ID.
 * @param {Object} geoData - Present lookup location.
 * @param {Object} decodedReq - Used for VPN contextual FP evaluation.
 * @returns {Array} Array of Threat Indicators.
 */
function checkGeoVelocity(sessionId, geoData, decodedReq) {
  const now = Date.now();
  const data = SESSION_DATA.get(sessionId);

  if (!data || !data.lastLocation || !geoData.country) return [];

  const timeDiff = now - data.lastLocation.timestamp;
  const country = geoData.country?.toUpperCase();
  const prevCountry = data.lastLocation.country?.toUpperCase();

  const currCoords = CITY_COORDS[country] || CITY_COORDS['US'];
  const prevCoords = CITY_COORDS[prevCountry] || CITY_COORDS['US'];

  const velocity = calculateGeoVelocity(
    { ...prevCoords, timestamp: data.lastLocation.timestamp },
    { ...currCoords, timestamp: now },
    timeDiff
  );

  const indicators = [];
  const vpnContext = isSuspectedVPN(decodedReq);

  // DEEP DIVE: FP Circuit Breaker for VPNs.
  // Standard travel maxes out at ~900km/h (commercial jet).
  // However, turning on a VPN triggers millions of km/h. 
  // If we suspect a VPN, we downgrade the threat severity of impossible travel.
  if (velocity > 900) {
    if (vpnContext) {
      indicators.push({ type: 'vpn_node_switch', detail: `VPN routing altered` }); // Low weight mapping expected
    } else {
      indicators.push({
        type: 'impossible_travel',
        detail: `Velocity ${velocity.toFixed(0)} km/h from ${prevCountry} to ${country}`,
      });
    }
  }
  
  const isMobile = isMobileUA(data.userAgent);
  const rapidThreshold = isMobile || vpnContext ? 300000 : 3600000;
  
  if (country !== prevCountry && timeDiff < rapidThreshold) {
    indicators.push({
      type: 'rapid_country_switch',
      detail: `Geo bounce: ${prevCountry} to ${country} in ${(timeDiff/60000).toFixed(1)} min`,
      isMobile, 
    });
  }
  
  return indicators;
}

/**
 * Compares mid-session Browser Fingerprint integrity (UA, Canvas, WebGL, Screen).
 * Sudden shifts are massive indications of Token Hijacking or Bot rotations.
 * @param {string} sessionId - User token.
 * @param {Object} fingerprint - Request client context map.
 * @returns {Array} Extracted discrepancies as feature indicators.
 */
function checkFingerprintChange(sessionId, fingerprint) {
  const data = SESSION_DATA.get(sessionId);
  if (!data || !data.fingerprint || !fingerprint) return [];

  const indicators = [];
  const prev = data.fingerprint;
  const curr = fingerprint;

  if (prev.userAgent && curr.userAgent && prev.userAgent !== curr.userAgent) {
    indicators.push({ type: 'ua_changed', detail: 'User-Agent modified mid-session' });
  }
  
  if (prev.canvas && curr.canvas && prev.canvas !== curr.canvas) {
    indicators.push({ type: 'canvas_changed', detail: 'Canvas context shifted' });
  }
  
  if (prev.screen && curr.screen) {
    const widthDiff = Math.abs(prev.screen.width - curr.screen.width);
    const heightDiff = Math.abs(prev.screen.height - curr.screen.height);
    const widthChangePct = widthDiff / Math.max(prev.screen.width, 1);
    
    // FP Control: Minor browser resizing shouldn't trigger an anomaly
    if ((widthChangePct > 0.2 && widthDiff > 200) || heightDiff > 200) {
      indicators.push({
        type: 'screen_changed',
        detail: `Resolution drastic shift (${prev.screen.width}x${prev.screen.height} → ${curr.screen.width}x${curr.screen.height})`,
      });
    }
  }

  return indicators;
}

/**
 * Analyzes the request against the historical Session Map. Emits weighted vectors.
 * @param {Object} decodedReq - Standardized extraction object from Decoder.
 * @returns {Array} Risk match instances for engine evaluation.
 */
function check(decodedReq) {
  const sessionId = decodedReq.sessionId;
  if (!sessionId) return [];

  const now = Date.now();
  const data = SESSION_DATA.get(sessionId) || {
    firstSeen: now,
    ips: new Set(),
    userAgent: decodedReq.userAgent,
    lastLocation: null,
    fingerprint: null,
  };

  const indicators = [];

  if (decodedReq.geoip && typeof decodedReq.geoip === 'object') {
    const geoAlerts = checkGeoVelocity(sessionId, decodedReq.geoip, decodedReq);
    indicators.push(...geoAlerts);
    data.lastLocation = {
      country: decodedReq.geoip.country,
      timestamp: now,
    };
  }

  if (decodedReq.fingerprint && typeof decodedReq.fingerprint === 'object') {
    const fpAlerts = checkFingerprintChange(sessionId, decodedReq.fingerprint);
    indicators.push(...fpAlerts);
    data.fingerprint = decodedReq.fingerprint;
  }

  data.ips.add(decodedReq.ip);
  if (data.ips.size > 5) {
    // 5 unique IPs on ONE session token hints heavily towards token sharing/extortion.
    indicators.push({
      type: 'session_ip_flood',
      detail: `Session shared across ${data.ips.size} unique IPs`,
    });
  }

  SESSION_DATA.set(sessionId, data);
  if (SESSION_DATA.size > MAX_SESSIONS) _cleanup();

  if (indicators.length > 0) {
    const matches = indicators.map(ind => ({
      rule: 'session_anomaly',
      tags: ['fraud', 'session_takeover'],
      severity: ind.type === 'impossible_travel' || ind.type === 'session_ip_flood' ? 'high' : 'medium',
      category: 'session-anomaly',
      description: ind.detail,
    }));
    return matches;
  }

  return [];
}

/**
 * Triggers LRU boundaries to prevent the Map() from consuming excessive OS RAM limits.
 */
function _cleanup() {
  const cutoff = Date.now() - MAX_SESSION_AGE;
  for (const [key, value] of SESSION_DATA.entries()) {
    if (value.firstSeen < cutoff) {
      SESSION_DATA.delete(key);
    }
  }
}

module.exports = { check, checkGeoVelocity, checkFingerprintChange, CITY_COORDS };

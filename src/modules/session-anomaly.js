'use strict';

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

function isMobileUA(userAgent) {
  return MOBILE_UA_PATTERN.test(userAgent || '');
}

function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
            Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
            Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}

function calculateGeoVelocity(prevLocation, currLocation, timeDiff) {
  if (!prevLocation || !currLocation || timeDiff <= 0) return 0;

  const distance = haversineDistance(
    prevLocation.lat, prevLocation.lon,
    currLocation.lat, currLocation.lon
  );

  const hours = timeDiff / (1000 * 60 * 60);
  return distance / hours;
}

function checkGeoVelocity(sessionId, geoData) {
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

  if (velocity > 900) {
    indicators.push({
      type: 'impossible_travel',
      detail: `Velocity ${velocity.toFixed(0)} km/h from ${prevCountry} to ${country}`,
    });
  }
  
  const isMobile = isMobileUA(data.userAgent);
  const rapidThreshold = isMobile ? 300000 : 3600000;
  if (country !== prevCountry && timeDiff < rapidThreshold) {
    indicators.push({
      type: 'rapid_country_switch',
      detail: `Country changed from ${prevCountry} to ${country} in ${(timeDiff/60000).toFixed(1)} min`,
      isMobile, // Used later for severity calculation
    });
  }
  
  return indicators;
}

function checkFingerprintChange(sessionId, fingerprint) {
  const data = SESSION_DATA.get(sessionId);
  if (!data || !data.fingerprint || !fingerprint) return [];

  const indicators = [];
  const prev = data.fingerprint;
  const curr = fingerprint;
  

  if (prev.userAgent && curr.userAgent && prev.userAgent !== curr.userAgent) {
    indicators.push({
      type: 'ua_changed',
      detail: 'User-Agent changed mid-session',
    });
  }
  
  if (prev.canvas && curr.canvas && prev.canvas !== curr.canvas) {
    indicators.push({
      type: 'canvas_changed',
      detail: 'Canvas fingerprint changed mid-session',
    });
  }
  
  if (prev.webgl && curr.webgl && prev.webgl !== curr.webgl) {
    indicators.push({
      type: 'webgl_changed',
      detail: 'WebGL fingerprint changed mid-session',
    });
  }
  
  if (prev.screen && curr.screen) {
    const widthDiff = Math.abs(prev.screen.width - curr.screen.width);
    const heightDiff = Math.abs(prev.screen.height - curr.screen.height);
    const widthChangePct = widthDiff / Math.max(prev.screen.width, 1);
    const heightChangePct = heightDiff / Math.max(prev.screen.height, 1);
    
    if ((widthChangePct > 0.2 && widthDiff > 200) || 
        (heightChangePct > 0.2 && heightDiff > 200)) {
      indicators.push({
        type: 'screen_changed',
        detail: `Screen resolution changed significantly (${prev.screen.width}x${prev.screen.height} → ${curr.screen.width}x${curr.screen.height})`,
      });
    }
  }
  
  return indicators;
}

function check(decodedReq) {
  const matches = [];
  const indicators = [];
  
  const sessionId = decodedReq.sessionId;
  if (!sessionId) return matches;
  
  const now = Date.now();
  let session = SESSION_DATA.get(sessionId);
  
  
  if (!session || (now - session.created) > MAX_SESSION_AGE) {
    session = {
      created: now,
      lastLocation: null,
      fingerprint: null,
      requestCount: 0,
    };
  }
  
  if (decodedReq.geoip) {
    const geoIndicators = checkGeoVelocity(sessionId, decodedReq.geoip);
    indicators.push(...geoIndicators);
    
    session.lastLocation = {
      country: decodedReq.geoip.country,
      timestamp: now,
    };
  }
  
  if (decodedReq.fingerprint) {
    const fpIndicators = checkFingerprintChange(sessionId, decodedReq.fingerprint);
    indicators.push(...fpIndicators);
    
    session.fingerprint = decodedReq.fingerprint;
  }
  
  
  if (session.knownIPs) {
    if (!session.knownIPs.includes(decodedReq.ip)) {
      if (session.knownIPs.length >= 2) {
        indicators.push({
          type: 'session_sharing',
          detail: `Session accessed from ${session.knownIPs.length + 1} different IPs`,
        });
      }
      session.knownIPs.push(decodedReq.ip);
    }
  } else {
    session.knownIPs = [decodedReq.ip];
  }
  
  session.requestCount++;
  session.userAgent = decodedReq.userAgent;

  if (SESSION_DATA.size >= MAX_SESSIONS) {
    const oldest = SESSION_DATA.keys().next().value;
    SESSION_DATA.delete(oldest);
  }
  
  SESSION_DATA.set(sessionId, session);
  
  if (indicators.length > 0) {
    const critical = indicators.some(i =>
      i.type === 'impossible_travel' || i.type === 'session_sharing'
    );

    const hasMobileGeo = indicators.some(i =>
      i.type === 'rapid_country_switch' && i.isMobile
    );
    const severity = critical ? 'critical' : (hasMobileGeo ? 'medium' : 'high');
    
    matches.push({
      rule: 'session_anomaly',
      tags: ['session', 'anomaly'],
      severity,
      category: 'session',
      description: `Session anomaly: ${indicators.map(i => i.type).join(', ')}`,
      author: 'laraxaar',
      sourceFile: 'builtin:session-anomaly',
      matchedPatterns: indicators.map(i => ({ 
        name: i.type, 
        matched: i.detail 
      })),
    });
  }
  
  return matches;
}


setInterval(() => {
  const now = Date.now();
  for (const [id, session] of SESSION_DATA.entries()) {
    if (now - session.created > MAX_SESSION_AGE) {
      SESSION_DATA.delete(id);
    }
  }
}, 300000); 

module.exports = { check };

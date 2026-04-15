/**
 * ShieldWall Dashboard — Frontend JavaScript
 * WebSocket client + DOM rendering for real-time attack monitoring
 */

(function() {
  'use strict';

  // ── State ──────────────────────────────────────────────
  const state = {
    connected: false,
    stats: { totalRequests: 0, blockedRequests: 0, detectedThreats: 0, rulesLoaded: 0, startTime: Date.now() },
    events: [],
    maxEvents: 200,
    severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    categories: {},
    ips: {},
  };

  // ── DOM Elements ───────────────────────────────────────
  const $ = (sel) => document.querySelector(sel);
  const el = {
    statusIndicator: $('#status-indicator'),
    statusText: $('#status-text'),
    uptime: $('#uptime'),
    statTotal: $('#stat-total'),
    statBlocked: $('#stat-blocked'),
    statThreats: $('#stat-threats'),
    statRules: $('#stat-rules'),
    feedList: $('#feed-list'),
    clearFeed: $('#clear-feed'),
    sevCritical: $('#sev-critical'),
    sevHigh: $('#sev-high'),
    sevMedium: $('#sev-medium'),
    sevLow: $('#sev-low'),
    sevCriticalCount: $('#sev-critical-count'),
    sevHighCount: $('#sev-high-count'),
    sevMediumCount: $('#sev-medium-count'),
    sevLowCount: $('#sev-low-count'),
    categoryList: $('#category-list'),
    ipList: $('#ip-list'),
  };

  // ── WebSocket Connection ───────────────────────────────
  let ws = null;
  let reconnectTimer = null;

  function connect() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${protocol}//${location.host}`;

    try {
      ws = new WebSocket(url);
    } catch (e) {
      scheduleReconnect();
      return;
    }

    ws.onopen = () => {
      state.connected = true;
      el.statusIndicator.classList.add('active');
      el.statusText.textContent = 'Connected';
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleMessage(msg);
      } catch (e) {
        console.error('Failed to parse message:', e);
      }
    };

    ws.onclose = () => {
      state.connected = false;
      el.statusIndicator.classList.remove('active');
      el.statusText.textContent = 'Disconnected';
      scheduleReconnect();
    };

    ws.onerror = () => {
      ws.close();
    };
  }

  function scheduleReconnect() {
    if (!reconnectTimer) {
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        connect();
      }, 3000);
    }
  }

  // ── Message Handlers ───────────────────────────────────
  function handleMessage(msg) {
    switch (msg.type) {
      case 'init':
        if (msg.data.stats) {
          Object.assign(state.stats, msg.data.stats);
        }
        if (msg.data.recentEvents) {
          for (const evt of msg.data.recentEvents) {
            processEvent(evt);
          }
        }
        updateUI();
        break;

      case 'log':
        processEvent(msg.data);
        updateUI();
        break;

      case 'threat':
        if (msg.data.matches) {
          for (const match of msg.data.matches) {
            const evt = {
              type: 'attack',
              action: msg.data.blocked ? 'blocked' : 'detected',
              rule: match.rule,
              severity: match.severity,
              category: match.category,
              description: match.description,
              ip: msg.data.request?.ip || 'unknown',
              method: msg.data.request?.method || 'GET',
              url: msg.data.request?.url || '/',
              timestamp: new Date().toISOString(),
            };
            processEvent(evt);
          }
        }
        state.stats.detectedThreats++;
        if (msg.data.blocked) state.stats.blockedRequests++;
        updateUI();
        break;
    }
  }

  function processEvent(evt) {
    if (evt.type !== 'attack') return;

    state.events.unshift(evt);
    if (state.events.length > state.maxEvents) {
      state.events.pop();
    }

    // Track severity
    const sev = evt.severity || 'medium';
    if (state.severity[sev] !== undefined) {
      state.severity[sev]++;
    }

    // Track categories
    const cat = evt.category || 'unknown';
    state.categories[cat] = (state.categories[cat] || 0) + 1;

    // Track IPs
    const ip = evt.ip || 'unknown';
    state.ips[ip] = (state.ips[ip] || 0) + 1;
  }

  // ── UI Rendering ───────────────────────────────────────
  function updateUI() {
    updateStats();
    updateFeed();
    updateSeverity();
    updateCategories();
    updateIPs();
  }

  function updateStats() {
    animateValue(el.statTotal, state.stats.totalRequests);
    animateValue(el.statBlocked, state.stats.blockedRequests);
    animateValue(el.statThreats, state.stats.detectedThreats);
    animateValue(el.statRules, state.stats.rulesLoaded || 0);
  }

  function animateValue(element, newValue) {
    const current = parseInt(element.textContent) || 0;
    if (current === newValue) return;
    element.textContent = newValue.toLocaleString();
    element.style.transform = 'scale(1.1)';
    element.style.color = '#818cf8';
    setTimeout(() => {
      element.style.transform = 'scale(1)';
      element.style.color = '';
    }, 300);
  }

  function updateFeed() {
    if (state.events.length === 0) {
      el.feedList.innerHTML = '<div class="feed-empty">Waiting for events...</div>';
      return;
    }

    const fragment = document.createDocumentFragment();
    const displayEvents = state.events.slice(0, 50);

    for (const evt of displayEvents) {
      const item = document.createElement('div');
      item.className = 'feed-item';
      
      const actionClass = evt.action === 'blocked' ? 'blocked' : 'detected';
      const actionLabel = evt.action === 'blocked' ? 'BLOCKED' : 'DETECTED';
      const time = evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : '';

      item.innerHTML = `
        <div class="feed-item__severity feed-item__severity--${evt.severity || 'medium'}"></div>
        <div class="feed-item__content">
          <div class="feed-item__header">
            <span class="feed-item__rule">${escapeHTML(evt.rule || 'unknown')}</span>
            <span class="feed-item__action feed-item__action--${actionClass}">${actionLabel}</span>
          </div>
          <div class="feed-item__desc">${escapeHTML(evt.description || '')}</div>
          <div class="feed-item__meta">
            <span>🌐 ${escapeHTML(evt.ip || 'unknown')}</span>
            <span>📡 ${escapeHTML(evt.method || 'GET')} ${escapeHTML(truncate(evt.url || '/', 40))}</span>
            <span>🕐 ${time}</span>
          </div>
        </div>
      `;
      fragment.appendChild(item);
    }

    el.feedList.innerHTML = '';
    el.feedList.appendChild(fragment);
  }

  function updateSeverity() {
    const total = Object.values(state.severity).reduce((a, b) => a + b, 0) || 1;

    for (const level of ['critical', 'high', 'medium', 'low']) {
      const count = state.severity[level] || 0;
      const pct = Math.min((count / total) * 100, 100);
      const bar = $(`#sev-${level}`);
      const countEl = $(`#sev-${level}-count`);
      if (bar) bar.style.width = `${pct}%`;
      if (countEl) countEl.textContent = count;
    }
  }

  function updateCategories() {
    const entries = Object.entries(state.categories)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);

    if (entries.length === 0) {
      el.categoryList.innerHTML = '<div class="feed-empty">No data yet</div>';
      return;
    }

    const categoryIcons = {
      'sqli': '💉',
      'xss': '🔴',
      'path-traversal': '📁',
      'traversal': '📁',
      'command-injection': '⚡',
      'cmdi': '⚡',
      'rate-limit': '⏱️',
      'scanner': '🤖',
      'protocol': '🔗',
    };

    el.categoryList.innerHTML = entries.map(([name, count]) => `
      <div class="category-item">
        <span class="category-item__name">${categoryIcons[name] || '🔹'} ${escapeHTML(name)}</span>
        <span class="category-item__count">${count}</span>
      </div>
    `).join('');
  }

  function updateIPs() {
    const entries = Object.entries(state.ips)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);

    if (entries.length === 0) {
      el.ipList.innerHTML = '<div class="feed-empty">No data yet</div>';
      return;
    }

    el.ipList.innerHTML = entries.map(([ip, count]) => `
      <div class="ip-item">
        <span class="ip-item__addr">${escapeHTML(ip)}</span>
        <span class="ip-item__count">${count}</span>
      </div>
    `).join('');
  }

  // ── Uptime Timer ───────────────────────────────────────
  function updateUptime() {
    const elapsed = Date.now() - (state.stats.startTime || Date.now());
    const hours = Math.floor(elapsed / 3600000);
    const minutes = Math.floor((elapsed % 3600000) / 60000);
    const seconds = Math.floor((elapsed % 60000) / 1000);
    el.uptime.textContent = `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
  }

  function pad(n) { return n.toString().padStart(2, '0'); }

  // ── Utilities ──────────────────────────────────────────
  function escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function truncate(str, maxLen) {
    return str.length > maxLen ? str.slice(0, maxLen) + '...' : str;
  }

  // ── Event Listeners ────────────────────────────────────
  el.clearFeed.addEventListener('click', () => {
    state.events = [];
    state.severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    state.categories = {};
    state.ips = {};
    updateUI();
  });

  // ── Init ───────────────────────────────────────────────
  connect();
  setInterval(updateUptime, 1000);

  // Fetch initial stats via REST as fallback
  fetch('/api/stats')
    .then(r => r.json())
    .then(data => {
      Object.assign(state.stats, data);
      updateStats();
    })
    .catch(() => {});

  fetch('/api/history')
    .then(r => r.json())
    .then(events => {
      for (const evt of events) {
        processEvent(evt);
      }
      updateUI();
    })
    .catch(() => {});

})();

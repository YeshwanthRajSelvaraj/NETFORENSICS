/**
 * NetForensics Browser Extension — Background Service Worker
 * ===========================================================
 * Captures network metadata (NO content capture):
 *   • Request URLs (domain portion only)
 *   • Connection timing (DNS, TCP, TLS handshake)
 *   • TLS certificate information
 *   • Request/response sizes
 *   • HTTP version
 *   • Security headers presence
 *
 * Sends metadata to NetForensics backend via WebSocket.
 */

// ─── Configuration ────────────────────────────────────────────────────────────
const CONFIG = {
  serverUrl: 'ws://localhost:8000/ws/extension',
  apiUrl: 'http://localhost:8000/api/v3/extension/ingest',
  batchSize: 50,
  flushIntervalMs: 10000,  // 10 seconds
  maxBufferSize: 500,
  enabled: true,
  captureUrls: false,      // Only capture domains by default (privacy)
  agentId: '',
};

// ─── State ────────────────────────────────────────────────────────────────────
let eventBuffer = [];
let ws = null;
let isConnected = false;
let stats = {
  totalRequests: 0,
  totalSent: 0,
  flaggedDomains: 0,
  sessionStart: Date.now(),
  errors: 0,
};

// ─── Initialize ───────────────────────────────────────────────────────────────
async function initialize() {
  // Generate or retrieve agent ID
  const stored = await chrome.storage.local.get(['agentId', 'config']);
  if (stored.agentId) {
    CONFIG.agentId = stored.agentId;
  } else {
    CONFIG.agentId = crypto.randomUUID();
    await chrome.storage.local.set({ agentId: CONFIG.agentId });
  }

  // Load saved config
  if (stored.config) {
    Object.assign(CONFIG, stored.config);
  }

  // Start flush timer
  chrome.alarms.create('flushBuffer', { periodInMinutes: CONFIG.flushIntervalMs / 60000 });
  
  console.log('[NetForensics] Extension initialized, agent:', CONFIG.agentId);
}

// ─── Request Listener ─────────────────────────────────────────────────────────
chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (!CONFIG.enabled) return;
    
    const url = new URL(details.url);
    
    // Skip extension's own requests and chrome internal
    if (url.protocol === 'chrome-extension:' || url.protocol === 'chrome:') return;

    const event = {
      timestamp: Date.now(),
      domain: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      protocol: url.protocol.replace(':', ''),
      method: details.method,
      status: details.statusCode,
      type: details.type,  // main_frame, script, stylesheet, image, etc.
      responseSize: details.responseHeaders ? 
        parseInt(details.responseHeaders.find(h => h.name.toLowerCase() === 'content-length')?.value || 0) : 0,
      initiator: details.initiator ? new URL(details.initiator).hostname : null,
      ip: details.ip || null,
      fromCache: details.fromCache || false,
    };

    // Capture URL path only if explicitly enabled
    if (CONFIG.captureUrls) {
      event.path = url.pathname;
    }

    // Check for security headers
    if (details.responseHeaders) {
      event.securityHeaders = {
        hsts: details.responseHeaders.some(h => h.name.toLowerCase() === 'strict-transport-security'),
        csp: details.responseHeaders.some(h => h.name.toLowerCase() === 'content-security-policy'),
        xframe: details.responseHeaders.some(h => h.name.toLowerCase() === 'x-frame-options'),
      };
    }

    eventBuffer.push(event);
    stats.totalRequests++;

    // Auto-flush if buffer is full
    if (eventBuffer.length >= CONFIG.batchSize) {
      flushBuffer();
    }
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

// ─── Connection Timing (Performance API via content script) ──────────────────
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!CONFIG.enabled) return;
    // Track request start time for timing calculation
    chrome.storage.session.set({ [`req_${details.requestId}`]: Date.now() });
  },
  { urls: ['<all_urls>'] }
);

// ─── Buffer Flush ─────────────────────────────────────────────────────────────
async function flushBuffer() {
  if (eventBuffer.length === 0) return;

  const batch = eventBuffer.splice(0, CONFIG.maxBufferSize);

  try {
    const response = await fetch(CONFIG.apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agent_id: CONFIG.agentId,
        events: batch,
      }),
    });

    if (response.ok) {
      const result = await response.json();
      stats.totalSent += batch.length;
      
      // Handle flagged domains
      if (result.flagged && result.flagged.length > 0) {
        stats.flaggedDomains += result.flagged.length;
        // Store flagged domains for popup display
        const stored = await chrome.storage.local.get(['flaggedDomains']);
        const existing = stored.flaggedDomains || [];
        const updated = [...result.flagged, ...existing].slice(0, 100);
        await chrome.storage.local.set({ flaggedDomains: updated });
        
        // Badge notification
        chrome.action.setBadgeText({ text: String(result.flagged.length) });
        chrome.action.setBadgeBackgroundColor({ color: '#FF3B30' });
        setTimeout(() => chrome.action.setBadgeText({ text: '' }), 30000);
      }
    } else {
      stats.errors++;
      // Put events back if send failed
      eventBuffer.unshift(...batch);
      if (eventBuffer.length > CONFIG.maxBufferSize) {
        eventBuffer = eventBuffer.slice(0, CONFIG.maxBufferSize);
      }
    }
  } catch (err) {
    stats.errors++;
    // Network error — buffer events for retry
    eventBuffer.unshift(...batch);
    if (eventBuffer.length > CONFIG.maxBufferSize) {
      eventBuffer = eventBuffer.slice(0, CONFIG.maxBufferSize);
    }
  }
}

// ─── Alarm Handler ────────────────────────────────────────────────────────────
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'flushBuffer') {
    flushBuffer();
  }
});

// ─── Message Handler (from popup) ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'getStats') {
    sendResponse({
      ...stats,
      bufferSize: eventBuffer.length,
      connected: isConnected,
      enabled: CONFIG.enabled,
      agentId: CONFIG.agentId,
      uptime: Math.round((Date.now() - stats.sessionStart) / 1000),
    });
    return true;
  }

  if (msg.type === 'toggleEnabled') {
    CONFIG.enabled = msg.enabled;
    chrome.storage.local.set({ config: CONFIG });
    sendResponse({ enabled: CONFIG.enabled });
    return true;
  }

  if (msg.type === 'updateServer') {
    CONFIG.apiUrl = msg.apiUrl;
    chrome.storage.local.set({ config: CONFIG });
    sendResponse({ updated: true });
    return true;
  }

  if (msg.type === 'flushNow') {
    flushBuffer().then(() => sendResponse({ flushed: true }));
    return true;
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
initialize();

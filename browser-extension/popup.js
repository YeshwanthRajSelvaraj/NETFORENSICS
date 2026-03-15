/**
 * NetForensics Extension — Popup Logic
 */

document.addEventListener('DOMContentLoaded', async () => {
  // Load stats from background
  refreshStats();
  setInterval(refreshStats, 2000);

  // Load flagged domains
  const stored = await chrome.storage.local.get(['flaggedDomains', 'config']);
  if (stored.flaggedDomains && stored.flaggedDomains.length > 0) {
    renderFlagged(stored.flaggedDomains);
  }
  if (stored.config && stored.config.apiUrl) {
    document.getElementById('serverUrl').value = stored.config.apiUrl;
  }

  // Toggle button
  document.getElementById('toggleBtn').addEventListener('click', async () => {
    const response = await chrome.runtime.sendMessage({ type: 'getStats' });
    const newState = !response.enabled;
    await chrome.runtime.sendMessage({ type: 'toggleEnabled', enabled: newState });
    updateToggleBtn(newState);
  });

  // Flush button
  document.getElementById('flushBtn').addEventListener('click', async () => {
    const btn = document.getElementById('flushBtn');
    btn.textContent = 'Flushing...';
    btn.disabled = true;
    await chrome.runtime.sendMessage({ type: 'flushNow' });
    btn.textContent = 'Flushed ✓';
    setTimeout(() => {
      btn.textContent = 'Flush Now';
      btn.disabled = false;
    }, 1500);
  });

  // Server URL update
  document.getElementById('serverUrl').addEventListener('change', async (e) => {
    await chrome.runtime.sendMessage({ type: 'updateServer', apiUrl: e.target.value });
  });
});

function refreshStats() {
  chrome.runtime.sendMessage({ type: 'getStats' }, (response) => {
    if (!response) return;

    document.getElementById('totalRequests').textContent = formatNumber(response.totalRequests);
    document.getElementById('totalSent').textContent = formatNumber(response.totalSent);
    document.getElementById('flaggedCount').textContent = formatNumber(response.flaggedDomains);
    document.getElementById('uptime').textContent = formatUptime(response.uptime);

    // Status pill
    const statusPill = document.getElementById('statusPill');
    const statusText = document.getElementById('statusText');
    if (response.enabled) {
      statusPill.className = 'status-pill';
      statusText.textContent = 'Active';
    } else {
      statusPill.className = 'status-pill warning';
      statusText.textContent = 'Paused';
    }

    updateToggleBtn(response.enabled);
  });
}

function renderFlagged(domains) {
  const list = document.getElementById('flaggedList');
  list.innerHTML = domains.slice(0, 10).map(d => `
    <div class="flagged-item">
      <span class="domain">${d.domain}</span>
      <span class="badge">${d.threat_type || d.severity || 'threat'}</span>
    </div>
  `).join('');
}

function updateToggleBtn(enabled) {
  const btn = document.getElementById('toggleBtn');
  if (enabled) {
    btn.textContent = 'Disable';
    btn.className = 'btn btn-danger';
  } else {
    btn.textContent = 'Enable';
    btn.className = 'btn btn-success';
  }
}

function formatNumber(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return String(n || 0);
}

function formatUptime(seconds) {
  if (seconds < 60) return seconds + 's';
  if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
  return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
}

/* Aegis Shield Dashboard — self-contained JS, no external dependencies */
'use strict';

// ── State ────────────────────────────────────────────────────────────────────────
const state = {
  apiKey: '',
  baseUrl: window.location.origin,
  connected: false,
  paused: false,
  eventCursor: 0,
  allEvents: [],
  pollTimer: null,
};

// ── Helpers ──────────────────────────────────────────────────────────────────────
function $(id) { return document.getElementById(id); }

function fmtBytes(n) {
  if (n >= 1e9) return (n / 1e9).toFixed(2) + ' GB/s';
  if (n >= 1e6) return (n / 1e6).toFixed(2) + ' MB/s';
  return (n / 1e3).toFixed(1) + ' KB/s';
}
function fmtNum(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}
function fmtTs(ns) {
  if (!ns) return '—';
  const ms = Math.floor(ns / 1e6);
  return new Date(ms).toLocaleTimeString();
}

async function apiFetch(path) {
  const resp = await fetch(state.baseUrl + path, {
    headers: { 'X-API-Key': state.apiKey },
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

// ── Status ────────────────────────────────────────────────────────────────────────
function applyStateClass(el, stateValue) {
  el.className = 'stat-value state-badge';
  if (stateValue) {
    el.classList.add('state-' + stateValue.toLowerCase().replace(/_/g, '_'));
  }
  el.textContent = stateValue || '—';
}

function updateContainmentVisual(s) {
  const label = $('containmentLabel');
  const icon = $('shieldIcon');
  const seq = $('containmentSeq');

  const stateColors = {
    normal: '#34d399',
    elevated: '#fbbf24',
    contained: '#ef4444',
    recovery_read_only: '#4f8ef7',
    fault: '#ef4444',
    maintenance: '#8892a4',
  };

  const color = stateColors[s.state] || 'var(--accent)';
  icon.style.setProperty('--shield-color', color);

  if (s.state === 'contained') {
    label.textContent = 'CONTAINED';
    label.style.color = 'var(--danger)';
    icon.style.filter = 'drop-shadow(0 0 12px #ef444480)';
    seq.textContent = s.containment_sequence != null ? `at sequence ${s.containment_sequence}` : '';
    showAlert('Containment active — writes are blocked', 'danger');
  } else if (s.state === 'elevated') {
    label.textContent = 'ELEVATED RISK';
    label.style.color = 'var(--warning)';
    icon.style.filter = 'drop-shadow(0 0 8px #fbbf2460)';
    seq.textContent = '';
    showAlert('Elevated risk state — monitoring closely', 'warning');
  } else if (s.state === 'recovery_read_only') {
    label.textContent = 'RECOVERY MODE';
    label.style.color = 'var(--accent)';
    icon.style.filter = 'drop-shadow(0 0 8px #4f8ef760)';
    seq.textContent = s.recovery_sequence != null ? `read-only at seq ${s.recovery_sequence}` : '';
    clearAlert();
  } else if (s.state === 'normal') {
    label.textContent = 'Protected';
    label.style.color = 'var(--success)';
    icon.style.filter = 'none';
    seq.textContent = '';
    clearAlert();
  } else {
    label.textContent = (s.state || '—').toUpperCase();
    label.style.color = '';
    icon.style.filter = 'none';
    seq.textContent = '';
    clearAlert();
  }
}

async function fetchStatus() {
  try {
    const s = await apiFetch('/v1/status');
    $('deviceId').textContent = s.device_id || '—';
    applyStateClass($('stateValue'), s.state);
    $('stateVersion').textContent = s.state_version ?? '—';
    $('lastSequence').textContent = s.last_sequence ?? '—';
    $('writesAllowed').textContent = s.writes_allowed ? '✓ Yes' : '✗ No';
    $('writesAllowed').style.color = s.writes_allowed ? 'var(--success)' : 'var(--danger)';
    $('journalBlocks').textContent = s.journal_capacity_blocks ?? '—';
    updateContainmentVisual(s);
    $('lastUpdated').textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    showAlert('Cannot reach daemon: ' + e.message, 'danger');
  }
}

async function fetchSizing() {
  try {
    const r = await apiFetch('/v1/sizing');
    $('pcieCeiling').textContent = fmtBytes(r.pcie_encoding_ceiling_bytes_s);
    $('payloadIops').textContent = fmtNum(r.payload_iops_ceiling);
    $('journalSec').textContent = r.ideal_journal_seconds.toFixed(1) + 's';
    $('maxPending').textContent = fmtNum(r.maximum_pending_blocks);
    $('writeAmp').textContent = r.proxy_write_amplification_lower_bound.toFixed(2) + '×';
  } catch (_) { /* sizing is optional */ }
}

// ── Events ────────────────────────────────────────────────────────────────────────
function renderEvents(events) {
  const tbody = $('eventsBody');
  if (events.length === 0 && state.allEvents.length === 0) return;

  const placeholder = tbody.querySelector('.placeholder-row');
  if (placeholder) placeholder.remove();

  const rows = events.map((ev, i) => {
    const absIdx = state.allEvents.length - events.length + i + 1;
    const tag = `<span class="event-tag tag-${ev.event || ''}">${ev.event || '?'}</span>`;
    const ts = `<span class="event-ts">${fmtTs(ev.timestamp_ns)}</span>`;
    const detail = JSON.stringify(ev.details || {});
    return `<tr>
      <td class="event-idx">${absIdx}</td>
      <td>${tag}</td>
      <td>${ts}</td>
      <td class="event-detail" title="${detail.replace(/"/g, '&quot;')}">${detail}</td>
    </tr>`;
  }).join('');

  tbody.insertAdjacentHTML('afterbegin', rows);

  while (tbody.rows.length > 2000) {
    tbody.deleteRow(tbody.rows.length - 1);
  }

  $('eventCount').textContent = `${state.allEvents.length} events`;
}

async function fetchEvents() {
  try {
    const data = await apiFetch(`/v1/events?after=${state.eventCursor}&limit=100`);
    if (data.events && data.events.length > 0) {
      state.allEvents.push(...data.events);
      state.eventCursor += data.events.length;
      renderEvents(data.events);
    }
  } catch (_) {}
}

// ── Poll loop ─────────────────────────────────────────────────────────────────────
async function poll() {
  if (!state.connected || state.paused) return;
  await fetchStatus();
  await fetchEvents();
}

function startPolling() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(poll, 5000);
  poll();
  fetchSizing();
}

// ── Alert banner ──────────────────────────────────────────────────────────────────
function showAlert(msg, type = 'danger') {
  const el = $('alertBanner');
  el.textContent = msg;
  el.className = 'alert-banner' + (type === 'warning' ? ' warning' : '');
}
function clearAlert() {
  $('alertBanner').className = 'alert-banner hidden';
}

// ── UI bindings ───────────────────────────────────────────────────────────────────
$('connectBtn').addEventListener('click', () => {
  const key = $('apiKeyInput').value.trim();
  if (!key) { showAlert('Enter your API key first'); return; }
  state.apiKey = key;
  state.connected = true;
  state.eventCursor = 0;
  state.allEvents = [];
  $('eventsBody').innerHTML = '';
  $('connectBtn').textContent = 'Reconnect';
  clearAlert();
  startPolling();
  try { sessionStorage.setItem('aegis_api_key', key); } catch (_) {}
});

$('pauseBtn').addEventListener('click', () => {
  state.paused = !state.paused;
  $('pauseBtn').textContent = state.paused ? 'Resume' : 'Pause';
});

$('clearBtn').addEventListener('click', () => {
  $('eventsBody').innerHTML = '<tr class="placeholder-row"><td colspan="4">Events cleared</td></tr>';
  state.allEvents = [];
  state.eventCursor = 0;
  $('eventCount').textContent = '0 events';
});

$('themeToggle').addEventListener('change', (e) => {
  document.documentElement.setAttribute('data-theme', e.target.checked ? 'light' : 'dark');
  try { localStorage.setItem('aegis_theme', e.target.checked ? 'light' : 'dark'); } catch (_) {}
});

try {
  const savedKey = sessionStorage.getItem('aegis_api_key');
  if (savedKey) { $('apiKeyInput').value = savedKey; }
  const savedTheme = localStorage.getItem('aegis_theme');
  if (savedTheme) {
    document.documentElement.setAttribute('data-theme', savedTheme);
    $('themeToggle').checked = savedTheme === 'light';
  }
} catch (_) {}

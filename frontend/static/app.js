/* Mini-SIEM v3 — Full Dashboard JS */
'use strict';

const API = {
  health:   '/health',
  events:   '/api/v1/events',
  alerts:   '/api/v1/alerts',
  stats:    '/api/v1/alerts/stats',
  statistics: '/api/v1/statistics',
  ioc:      '/api/v1/analyze-ioc',
  iocCheck: '/api/v1/ioc/check',
  packet:   '/api/v1/analyze-packet',
  upload:   '/api/v1/upload-log',
  history:  '/api/v1/upload-history',
};

const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

let currentPage   = 0;
let currentFilter = '';
const PAGE_SIZE   = 25;

/* ── Fetch helpers ────────────────────────────────────────────────────────── */
async function fetchJson(url, opts = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data;
}

function sev(s) {
  const m = { critical: 'pill-critical', high: 'pill-high', medium: 'pill-medium', low: 'pill-low' };
  return `<span class="pill ${m[(s||'').toLowerCase()] || 'pill-low'}">${s || 'N/A'}</span>`;
}

function ts(raw) {
  if (!raw) return '—';
  try { return new Date(raw).toLocaleString(); } catch { return raw; }
}

function truncate(s, n = 60) {
  if (!s) return '—';
  return s.length > n ? s.slice(0, n) + '…' : s;
}

/* ── Tab switching ────────────────────────────────────────────────────────── */
$$('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('.tab').forEach(t => t.classList.remove('active'));
    $$('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    $(`#tab-${btn.dataset.tab}`).classList.add('active');
    if (btn.dataset.tab === 'dashboard') loadDashboard();
    if (btn.dataset.tab === 'alerts')    loadAlerts();
    if (btn.dataset.tab === 'upload')    loadHistory();
  });
});

/* ── Health check ─────────────────────────────────────────────────────────── */
async function loadHealth() {
  const dot  = $('#healthDot');
  const txt  = $('#healthText');
  try {
    const d = await fetchJson(API.health);
    dot.className = 'health-dot online';
    txt.textContent = `v${d.version} · ML: ${d.ml_enabled ? '✓' : '✗'} · IOC: ${d.ioc_live_lookup ? 'Live' : 'Sim'}`;

    // Update ML info panel
    const mlInfo = $('#mlInfo');
    if (mlInfo) mlInfo.innerHTML = `
      <p><strong>ML Engine:</strong> <span class="${d.ml_enabled ? 'ok' : 'muted'}">${d.ml_enabled ? 'Active (Random Forest)' : 'Disabled'}</span></p>
      <p><strong>IOC Lookup:</strong> ${d.ioc_live_lookup ? '<span class="ok">Live API</span>' : '<span class="muted">Offline Simulation</span>'}</p>
      <p><strong>Version:</strong> ${d.version}</p>
      <p class="muted small" style="margin-top:8px">The RF model classifies network traffic into Benign, PortScan, DDoS, etc. based on packet-level features.</p>
    `;
  } catch {
    dot.className = 'health-dot offline';
    txt.textContent = 'Offline';
  }
}

/* ── Dashboard ────────────────────────────────────────────────────────────── */
async function loadDashboard() {
  try {
    const stats = await fetchJson(API.statistics);

    // Severity counters
    const sv = stats.by_severity || {};
    $('#stat-critical').textContent = sv.Critical || 0;
    $('#stat-high').textContent     = sv.High     || 0;
    $('#stat-medium').textContent   = sv.Medium   || 0;
    $('#stat-low').textContent      = sv.Low      || 0;
    $('#stat-total').textContent    = stats.total_alerts || 0;
    $('#stat-uploads').textContent  = stats.upload_count || 0;
    $('#stat-malicious').textContent = stats.ioc_stats?.malicious_count || 0;

    // MITRE chart
    renderBarChart('#mitre-chart', stats.by_mitre_tactic || {}, '#7c6ff9');
    // IP chart
    const ipData = {};
    (stats.top_source_ips || []).forEach(r => { ipData[r.ip] = r.count; });
    renderBarChart('#ip-chart', ipData, '#f43f5e');

    // Recent alerts
    const recent = stats.recent_activity || [];
    if (!recent.length) {
      $('#recent-alerts').innerHTML = '<p class="muted">No alerts yet. Upload a log file to get started.</p>';
    } else {
      $('#recent-alerts').innerHTML = `
        <table class="siem-table">
          <thead><tr><th>ID</th><th>Event</th><th>Severity</th><th>IP</th><th>MITRE Tactic</th><th>Time</th></tr></thead>
          <tbody>${recent.map(a => `
            <tr onclick="showAlertDetail(${a.id})" style="cursor:pointer">
              <td>#${a.id}</td>
              <td>${truncate(a.event_type, 30)}</td>
              <td>${sev(a.severity)}</td>
              <td><code>${a.source_ip}</code></td>
              <td>${a.mitre_tactic ? `<span class="tag">${a.mitre_tactic}</span>` : '—'}</td>
              <td class="muted">${ts(a.created_at)}</td>
            </tr>`).join('')}
          </tbody>
        </table>`;
    }
  } catch (e) {
    console.error('Dashboard load error:', e);
  }
}

function renderBarChart(sel, data, color = '#4f9cf9') {
  const el = $(sel);
  if (!el) return;
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (!entries.length) { el.innerHTML = '<p class="muted small">No data yet.</p>'; return; }
  const max = entries[0][1] || 1;
  el.innerHTML = entries.map(([label, count]) => `
    <div class="bar-row">
      <span class="bar-label" title="${label}">${label}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${(count/max*100).toFixed(1)}%;background:${color}"></div></div>
      <span class="bar-count">${count}</span>
    </div>`).join('');
}

/* ── Alerts table ─────────────────────────────────────────────────────────── */
async function loadAlerts(page = currentPage, filter = currentFilter) {
  currentPage   = page;
  currentFilter = filter;
  const offset  = page * PAGE_SIZE;
  const url = `${API.alerts}?limit=${PAGE_SIZE}&offset=${offset}${filter ? '&severity=' + filter : ''}`;
  try {
    const data = await fetchJson(url);
    renderAlertsTable(data.alerts);
    renderPagination(data.total, page);
  } catch (e) {
    $('#alertsTable').innerHTML = `<p class="err">${e.message}</p>`;
  }
}

function renderAlertsTable(alerts) {
  if (!alerts.length) {
    $('#alertsTable').innerHTML = '<p class="muted" style="padding:16px">No alerts found. Upload a log file to generate alerts automatically.</p>';
    return;
  }
  $('#alertsTable').innerHTML = `
    <table class="siem-table">
      <thead><tr>
        <th>ID</th><th>Rule / Event</th><th>Severity</th><th>Source IP</th>
        <th>MITRE</th><th>IOC</th><th>ML</th><th>User</th><th>Time</th>
      </tr></thead>
      <tbody>${alerts.map(a => `
        <tr onclick="showAlertDetail(${a.id})">
          <td>#${a.id}</td>
          <td><span title="${a.event_type}">${truncate(a.rule_name || a.event_type, 28)}</span></td>
          <td>${sev(a.severity)}</td>
          <td><code>${a.source_ip}</code></td>
          <td>${a.mitre_technique_id ? `<span class="mitre-badge">${a.mitre_technique_id}</span>` : '—'}</td>
          <td>${a.ioc_malicious === true ? '<span class="err">⚠ Malicious</span>' : a.ioc_reputation ? `<span class="muted">${truncate(a.ioc_reputation,18)}</span>` : '—'}</td>
          <td>${a.ml_prediction && a.ml_prediction !== 'unavailable' ? `<code>${a.ml_prediction}</code>` : '—'}</td>
          <td>${a.username || '—'}</td>
          <td class="muted">${ts(a.created_at)}</td>
        </tr>`).join('')}
      </tbody>
    </table>`;
}

function renderPagination(total, page) {
  const pages = Math.ceil(total / PAGE_SIZE);
  if (pages <= 1) { $('#pagination').innerHTML = ''; return; }
  let html = '';
  for (let i = 0; i < Math.min(pages, 10); i++) {
    html += `<button class="page-btn${i === page ? ' active' : ''}" onclick="loadAlerts(${i},'${currentFilter}')">${i + 1}</button>`;
  }
  $('#pagination').innerHTML = html;
}

/* ── Alert detail overlay ─────────────────────────────────────────────────── */
async function showAlertDetail(id) {
  const overlay = $('#alertDetailOverlay');
  const content = $('#alertDetailContent');
  content.innerHTML = '<p class="muted">Loading…</p>';
  overlay.style.display = 'flex';
  try {
    const a = await fetchJson(`${API.alerts}/${id}`);
    content.innerHTML = `
      <div class="detail-grid">
        <div class="detail-kv"><div class="dk">ID</div><div class="dv">#${a.id}</div></div>
        <div class="detail-kv"><div class="dk">Severity</div><div class="dv">${sev(a.severity)}</div></div>
        <div class="detail-kv"><div class="dk">Event Type</div><div class="dv">${a.event_type}</div></div>
        <div class="detail-kv"><div class="dk">Rule</div><div class="dv">${a.rule_name || '—'}</div></div>
        <div class="detail-kv"><div class="dk">Source IP</div><div class="dv"><code>${a.source_ip}</code></div></div>
        <div class="detail-kv"><div class="dk">Username</div><div class="dv">${a.username || '—'}</div></div>
        <div class="detail-kv"><div class="dk">IOC Reputation</div><div class="dv ${a.ioc_malicious ? 'err' : 'ok'}">${a.ioc_reputation || '—'} ${a.ioc_malicious ? '⚠' : ''}</div></div>
        <div class="detail-kv"><div class="dk">IOC Provider</div><div class="dv">${a.ioc_provider || '—'}</div></div>
        <div class="detail-kv"><div class="dk">ML Prediction</div><div class="dv">${a.ml_prediction || '—'}</div></div>
        <div class="detail-kv"><div class="dk">Time</div><div class="dv">${ts(a.created_at)}</div></div>
        ${a.mitre_technique_id ? `
        <div class="mitre-block">
          <h4>🛡 MITRE ATT&CK</h4>
          <div class="mitre-row">
            <span class="mitre-badge">${a.mitre_technique_id}</span>
            <span class="tag">${a.mitre_technique_name}</span>
            <span class="tag">${a.mitre_tactic}</span>
          </div>
        </div>` : ''}
        <div class="detail-desc">${a.description}</div>
      </div>`;
  } catch (e) {
    content.innerHTML = `<p class="err">${e.message}</p>`;
  }
}

$('#closeDetail').addEventListener('click', () => {
  $('#alertDetailOverlay').style.display = 'none';
});
$('#alertDetailOverlay').addEventListener('click', e => {
  if (e.target === $('#alertDetailOverlay')) $('#alertDetailOverlay').style.display = 'none';
});

/* ── Alerts filter ────────────────────────────────────────────────────────── */
$('#applyFilter').addEventListener('click', () => {
  loadAlerts(0, $('#filterSeverity').value);
});
$('#reloadAlerts').addEventListener('click', () => loadAlerts(0, currentFilter));
$('#filterSeverity').addEventListener('change', () => loadAlerts(0, $('#filterSeverity').value));

/* ── Log file upload ──────────────────────────────────────────────────────── */
const uploadZone  = $('#uploadZone');
const fileInput   = $('#logFileInput');
const browseBtn   = $('#browseBtn');
const progressWrap = $('#uploadProgress');
const progressFill = $('#progressFill');
const progressText = $('#progressText');

browseBtn.addEventListener('click', () => fileInput.click());
uploadZone.addEventListener('click', e => { if (e.target !== browseBtn) fileInput.click(); });

uploadZone.addEventListener('dragover', e => {
  e.preventDefault();
  uploadZone.classList.add('drag-over');
});
uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag-over'));
uploadZone.addEventListener('drop', e => {
  e.preventDefault();
  uploadZone.classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if (f) processUpload(f);
});
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) processUpload(fileInput.files[0]);
});

async function processUpload(file) {
  const resultEl = $('#uploadResult');
  resultEl.innerHTML = '';
  $('#uploadAlertsPanel').style.display = 'none';

  // Show progress
  progressWrap.style.display = 'block';
  progressFill.style.width = '0%';
  progressText.textContent = `Reading ${file.name}…`;

  // Animate progress
  let prog = 0;
  const timer = setInterval(() => {
    prog = Math.min(prog + 8, 85);
    progressFill.style.width = prog + '%';
  }, 200);

  try {
    const fd = new FormData();
    fd.append('file', file);
    progressText.textContent = 'Parsing events…';

    const res = await fetch(API.upload, { method: 'POST', body: fd });
    const data = await res.json().catch(() => ({}));

    clearInterval(timer);

    if (!res.ok) {
      progressFill.style.width = '100%';
      progressFill.style.background = '#f43f5e';
      progressText.textContent = 'Failed.';
      resultEl.innerHTML = `<div class="upload-result-card error">
        <p class="err">❌ ${data.detail || 'Upload failed'}</p>
      </div>`;
      return;
    }

    progressFill.style.width = '100%';
    progressText.textContent = 'Done!';

    // Render result
    const d = data;
    const ioc = d.iocs_found || {};
    resultEl.innerHTML = `
      <div class="upload-result-card">
        <p style="font-weight:700;margin-bottom:10px">✅ ${d.message}</p>
        <div class="result-row">
          <div class="result-kv"><div class="k">Format Detected</div><div class="v" style="font-size:14px;text-transform:uppercase">${d.log_format}</div></div>
          <div class="result-kv"><div class="k">Events Parsed</div><div class="v">${d.total_events}</div></div>
          <div class="result-kv"><div class="k">Alerts Generated</div><div class="v" style="color:#f43f5e">${d.total_alerts}</div></div>
          <div class="result-kv"><div class="k">IPs Found</div><div class="v">${(ioc.ips||[]).length}</div></div>
          <div class="result-kv"><div class="k">Domains</div><div class="v">${(ioc.domains||[]).length}</div></div>
          <div class="result-kv"><div class="k">Hashes</div><div class="v">${(ioc.hashes||[]).length}</div></div>
        </div>
        ${d.detections_summary && d.detections_summary.length ? `
        <p style="font-weight:600;margin-bottom:6px;font-size:13px">Detections:</p>
        <div class="detection-list">
          ${d.detections_summary.map(det => `
            <div class="detection-item">
              ${sev(det.severity)}
              <span style="flex:1;font-weight:600">${det.rule}</span>
              ${det.mitre ? `<span class="mitre-badge">${det.mitre}</span>` : ''}
              <span class="muted small">IP: ${det.ip}</span>
              <span class="muted small">→ Alert #${det.alert_id}</span>
            </div>`).join('')}
        </div>` : '<p class="muted small" style="margin-top:8px">No threats detected in this file.</p>'}
      </div>`;

    // Show alerts from this upload
    if (d.alerts_created && d.alerts_created.length) {
      $('#uploadAlertsPanel').style.display = 'block';
      await loadUploadAlerts(d.upload_id);
    }

    // Refresh history and dashboard
    await loadHistory();
    loadDashboard();

  } catch (e) {
    clearInterval(timer);
    progressFill.style.width = '100%';
    progressFill.style.background = '#f43f5e';
    progressText.textContent = 'Error.';
    resultEl.innerHTML = `<div class="upload-result-card error"><p class="err">❌ ${e.message}</p></div>`;
  } finally {
    fileInput.value = '';
  }
}

async function loadUploadAlerts(uploadId) {
  try {
    const data = await fetchJson(`${API.alerts}?upload_id=${uploadId}&limit=50`);
    const container = $('#uploadAlerts');
    if (!data.alerts.length) {
      container.innerHTML = '<p class="muted">No alerts from this upload.</p>';
      return;
    }
    container.innerHTML = `
      <table class="siem-table">
        <thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>IP</th><th>MITRE</th><th>IOC</th></tr></thead>
        <tbody>${data.alerts.map(a => `
          <tr onclick="showAlertDetail(${a.id})" style="cursor:pointer">
            <td>#${a.id}</td>
            <td>${truncate(a.rule_name || a.event_type, 35)}</td>
            <td>${sev(a.severity)}</td>
            <td><code>${a.source_ip}</code></td>
            <td>${a.mitre_technique_id ? `<span class="mitre-badge">${a.mitre_technique_id}</span>` : '—'}</td>
            <td>${a.ioc_malicious ? '<span class="err">⚠ Malicious</span>' : `<span class="ok">${a.ioc_reputation || 'clean'}</span>`}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  } catch (e) {
    $('#uploadAlerts').innerHTML = `<p class="err">${e.message}</p>`;
  }
}

/* ── Upload history ───────────────────────────────────────────────────────── */
async function loadHistory() {
  const el = $('#uploadHistory');
  try {
    const data = await fetchJson(API.history);
    if (!data.uploads.length) {
      el.innerHTML = '<p class="muted">No uploads yet.</p>';
      return;
    }
    el.innerHTML = data.uploads.map(u => `
      <div class="history-item">
        <div class="history-icon">${u.status === 'done' ? '✅' : u.status === 'error' ? '❌' : '⏳'}</div>
        <div class="history-info">
          <div class="history-name">${u.filename}</div>
          <div class="history-meta">${u.total_events} events · ${u.total_alerts} alerts · ${new Date(u.created_at).toLocaleString()}</div>
        </div>
        <span class="history-badge status-${u.status}">${u.status}</span>
      </div>`).join('');
  } catch (e) {
    el.innerHTML = `<p class="err">${e.message}</p>`;
  }
}

$('#refreshHistory').addEventListener('click', loadHistory);

/* ── IOC Lookup ───────────────────────────────────────────────────────────── */
$('#iocForm').addEventListener('submit', async e => {
  e.preventDefault();
  const val = new FormData(e.target).get('value');
  await doIocLookup(val);
});

window.testIOC = async (val) => {
  $('input[name="value"]', $('#iocForm')).value = val;
  await doIocLookup(val);
};

async function doIocLookup(val) {
  const el = $('#iocResult');
  el.textContent = 'Looking up…';
  try {
    const data = await fetchJson(API.ioc, {
      method: 'POST',
      body: JSON.stringify({ value: val }),
    });
    const r = data.result;
    const sum = r.summary || {};
    el.innerHTML = `<div style="margin-bottom:8px">
      <strong style="font-size:15px">${r.ioc}</strong>
      <span class="tag" style="margin-left:8px">${r.type || 'unknown'}</span>
      <span class="pill ${sum.is_malicious ? 'pill-critical' : 'pill-low'}" style="margin-left:8px">
        ${sum.is_malicious ? '⚠ MALICIOUS' : '✓ CLEAN'}
      </span>
    </div>
    <div style="margin-bottom:8px"><span class="muted">Reputation:</span> <strong>${sum.reputation || '—'}</strong> · <span class="muted">Provider:</span> <strong>${sum.provider || '—'}</strong></div>
    <div style="font-size:12px;color:var(--muted)">
      <strong>VirusTotal:</strong> ${r.virustotal ? `malicious: ${r.virustotal.malicious ?? '—'}, suspicious: ${r.virustotal.suspicious ?? '—'}` : '—'}<br>
      <strong>AbuseIPDB:</strong> ${r.abuseipdb ? `score: ${r.abuseipdb.abuse_score ?? '—'}, reports: ${r.abuseipdb.total_reports ?? '—'}, country: ${r.abuseipdb.country || '—'}` : '—'}<br>
      <strong>AlienVault OTX:</strong> ${r.alienvault ? `pulses: ${r.alienvault.pulse_count ?? '—'}, families: ${(r.alienvault.malware_families || []).join(', ') || '—'}` : '—'}
    </div>`;
  } catch (e) {
    el.textContent = `Error: ${e.message}`;
  }
}

/* ── Manual event ingest ──────────────────────────────────────────────────── */
// Set default timestamp
const tsInput = $('#timestampInput');
if (tsInput) tsInput.value = new Date().toISOString().slice(0, 19) + 'Z';

$('#eventForm').addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = Object.fromEntries(fd.entries());
  const el = $('#eventResult');
  el.textContent = 'Submitting…';
  try {
    const data = await fetchJson(API.events, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    el.innerHTML = `<span class="ok">✅ Alert #${data.alert_id} created — ${data.message}</span>`;
    loadDashboard();
    loadAlerts();
  } catch (err) {
    el.innerHTML = `<span class="err">❌ ${err.message}</span>`;
  }
});

// Quick event buttons
$$('.quick-event-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    const ev = JSON.parse(btn.dataset.event);
    const form = $('#eventForm');
    form.event_type.value = ev.event_type;
    form.severity.value   = ev.severity;
    form.source_ip.value  = ev.source_ip;
    form.description.value = ev.description;
    form.timestamp.value  = new Date().toISOString().slice(0, 19) + 'Z';
    // Auto-submit
    const el = $('#eventResult');
    el.textContent = 'Submitting…';
    try {
      const data = await fetchJson(API.events, {
        method: 'POST',
        body: JSON.stringify({ ...ev, timestamp: form.timestamp.value }),
      });
      el.innerHTML = `<span class="ok">✅ Alert #${data.alert_id} created — ${data.message}</span>`;
      loadDashboard();
    } catch (err) {
      el.innerHTML = `<span class="err">❌ ${err.message}</span>`;
    }
  });
});

/* ── ML packet analysis ───────────────────────────────────────────────────── */
$('#packetForm').addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = {};
  fd.forEach((v, k) => { payload[k] = parseFloat(v); });
  const el = $('#packetResult');
  el.textContent = 'Running ML classifier…';
  try {
    const data = await fetchJson(API.packet, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    const r = data.result;
    el.innerHTML = r.ml_enabled === false
      ? '<span class="muted">ML engine not available (model not loaded)</span>'
      : `<span class="${r.is_malicious ? 'err' : 'ok'}" style="font-size:16px;font-weight:800">${r.is_malicious ? '⚠ ' : '✓ '}${r.prediction}</span>
         <br><span class="muted small">ML enabled: ${r.ml_enabled} · Malicious: ${r.is_malicious}</span>`;
  } catch (err) {
    el.innerHTML = `<span class="err">❌ ${err.message}</span>`;
  }
});

// Quick packet scenarios
$$('.quick-packet-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const features = JSON.parse(btn.dataset.features);
    const form = $('#packetForm');
    Object.entries(features).forEach(([k, v]) => {
      const inp = form.querySelector(`[name="${k}"]`);
      if (inp) inp.value = v;
    });
  });
});

/* ── Refresh all ──────────────────────────────────────────────────────────── */
$('#refreshAll').addEventListener('click', () => {
  loadHealth();
  loadDashboard();
});

/* ── Init ─────────────────────────────────────────────────────────────────── */
loadHealth();
loadDashboard();
loadHistory();

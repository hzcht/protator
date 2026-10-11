const $ = (s) => document.querySelector(s);
const pageSize = 1000;
let listed = []; // rows currently rendered in the proxies table

const el = (tag, text, cls) => {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (cls) n.className = cls;
  return n;
};
const num = (n) => (n === undefined || n === null ? '-' : n.toLocaleString());

function toast(msg, isErr) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show' + (isErr ? ' err' : '');
  clearTimeout(t._h);
  t._h = setTimeout(() => { t.className = 'toast'; }, 4000);
}

// The admin token, when server.admin_token is set. Read once from the URL
// (?token=...) so a link works, then remembered: the page reloads often and
// pasting a token per tab is how people stop using a security control.
let TOKEN = null;
try {
  const q = new URLSearchParams(location.search).get('token');
  if (q) {
    TOKEN = q;
    localStorage.setItem('protator_token', q);
    // Strip ?token= from the address bar and history: the token is now in
    // localStorage, and a secret that stays in the URL lands in browser
    // history, shoulder-surfing screenshots and proxy logs.
    const u = new URL(location.href);
    u.searchParams.delete('token');
    history.replaceState(null, '', u.pathname + u.search + u.hash);
  } else { TOKEN = localStorage.getItem('protator_token') || null; }
} catch (e) { /* private mode: tokens simply do not persist */ }

function withToken(url) {
  if (!TOKEN) return url;
  return url + (url.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(TOKEN);
}

async function get(url) {
  const r = await fetch(withToken(url), { cache: 'no-store' });
  if (r.status === 401) {
    TOKEN = prompt('admin token:') || null;
    if (TOKEN) { try { localStorage.setItem('protator_token', TOKEN); } catch (e) {} }
    if (!TOKEN) throw new Error('admin token required');
    return get(url);
  }
  if (!r.ok) throw new Error(url + ' -> HTTP ' + r.status);
  return r.json();
}

async function post(method, url, payload) {
  const r = await fetch(withToken(url), {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload || {}),
  });
  const j = await r.json().catch(() => ({ error: 'HTTP ' + r.status }));
  if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
  return j;
}

function tile(k, v, title) {
  const t = el('div', undefined, 'tile');
  if (title) t.title = title;
  t.append(el('span', k, 'k'), el('span', String(v), 'v'));
  return t;
}

function ageStr(s) {
  if (s === undefined || s === null) return '-';
  s = Math.floor(s);
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  return Math.floor(s / 3600) + 'h';
}

// renderTiles is shared by the HTTP poll and the WebSocket push: two copies
// of this list drifted before (the WS path lagged every new signal), so both
// call this one function.
function renderTiles(h) {
  const reqTitle = 'per front — http ' + num(h.http_requests_total) +
    ' · connect ' + num(h.connect_requests_total) +
    ' · socks5 ' + num(h.socks5_sessions_total);
  $('#tiles').replaceChildren(
    tile('live', num(h.queue_live)),
    tile('proven', num(h.queue_proven)),
    tile('hot', num(h.queue_hot)),
    tile('pool', num(h.pool_candidates)),
    tile('req', num(h.requests_total), reqTitle),
    tile('served', num(h.served_ok_total)),
    tile('servefail', num(h.serve_failures_total)),
    tile('dialfail', num(h.dial_failures_total)),
    tile('blocks', num(h.block_pages_total)),
    tile('checks', num(h.checks_total)),
    tile('panics', num(h.recovered_panics_total),
      'recovered panics process-wide — a climbing number is the bug report'),
    tile('restarts', num(h.worker_restarts),
      'checker worker restarts — the supervisor restarts a worker that exits'),
    tile('uptime', Math.floor(h.uptime_seconds / 60) + 'm'),
    tile('tls', h.tls ? 'yes' : 'no'),
  );
  // Subsystem freshness: a crashed collector and a merely-slow one look
  // identical in counters; ages tell them apart. One stale subsystem is the
  // first thing to check when the numbers stop moving.
  const beat = $('#beats');
  if (beat) {
    if (!h.beats) { beat.textContent = ''; }
    else {
      const b = h.beats;
      const part = (label, age, stale) =>
        label + ' ' + ageStr(age) + (stale ? ' STALE' : '');
      beat.textContent = part('collector', b.collector_age_s, b.collector_stale) + ' · ' +
        part('revalidate', b.revalidate_age_s, b.revalidate_stale) + ' · ' +
        part('save', b.save_age_s, b.save_stale);
    }
  }
}

async function loadHealth() {
  const h = await get('/health');
  renderTiles(h);
  // The wake button is the *remedy* for a stale collector: enable it when
  // the collector is stale (the moment it is needed), not disable it.
  $('#wake').disabled = !!h.beats && !h.beats.collector_stale;
  $('#wake').title = h.beats && h.beats.collector_stale
    ? 'Collector has not run a cycle recently - collecting now is the fix'
    : 'Force a collector cycle now (the site list is re-read)';
}

// loadProxies fetches initial proxies via HTTP (fallback before WS connects)
async function loadProxies() {
  const scope = $('#scope').value;
  const country = $('#country').value.trim();
  const asn = $('#asn').value.trim();
  let url = '/api/proxies?scope=' + encodeURIComponent(scope) + '&limit=' + pageSize;
  if (country) url += '&country=' + encodeURIComponent(country);
  if (asn) url += '&asn=' + encodeURIComponent(asn);
  const d = await get(url);
  $('#proxyCount').textContent = d.total > d.count
    ? num(d.count) + ' best of ' + num(d.total) + ' in scope (window ' +
      Math.round(d.window_seconds / 60) + ' min)'
    : num(d.count) + ' in scope, window ' + Math.round(d.window_seconds / 60) + ' min';
  const base = '/api/proxies?scope=' + encodeURIComponent(scope);
  $('#download').href = withToken(base + '&format=text');
  $('#downloadCsv').href = withToken(base + '&format=csv');
  renderProxies(d.proxies);
}

function tr(cells) {
  const row = el('tr');
  for (const c of cells) {
    const td = el('td');
    if (c && c.nodeType) td.append(c); else td.textContent = String(c);
    row.append(td);
  }
  return row;
}

// retestButton asks the checker to re-validate one proxy now: dead entries are
// dropped, live ones get a fresh stamp. The pick evidence on the page is only
// as good as the last check, and "is this one really alive" is the question an
// operator asks most.
function retestButton(urls, label) {
  const b = el('button', label || 'retest', '');
  b.title = 'Re-check through the full validator now';
  b.onclick = async () => {
    b.disabled = true;
    try {
      const j = await post('POST', '/api/proxies/revalidate', { urls });
      const n = j.revalidated || 0;
      toast(n ? 're-checking ' + n + ' proxy(ies); live ones stay, dead are dropped'
              : 'nothing matched a live queue entry');
    } catch (e) { toast(e.message, true); b.disabled = false; }
  };
  return b;
}

function proxyCells(p) {
  const proof = p.served ? 'served' : (p.checked ? 'validated' : 'queued');
  const cls = p.served ? 'ok' : (p.checked ? 'warn' : 'muted');
  return [
    p.url, p.schema || '-', p.latency_ms + ' ms',
    p.ok_total + '/' + p.fail_total,
    Math.round(p.proof_age_s) + ' s',
    el('span', proof, 'tag ' + cls),
    p.source || '-',
    copyButton(p.url),
    retestButton([p.url]),
    dropButton(p.url),
  ];
}

// dropButton removes one proxy from the live queue now — the operator
// override for a burned exit IP or a poisoned entry that validates fine.
// Confirm-gated like the site delete: there is no undo short of the next
// collector cycle re-adding the address.
function dropButton(url) {
  const b = el('button', 'drop', '');
  b.title = 'Remove from the live queue now (no re-check)';
  b.onclick = async () => {
    if (!confirm('Drop ' + url + ' from the live queue?')) return;
    b.disabled = true;
    try {
      const j = await post('POST', '/api/proxies/drop', { urls: [url] });
      if (j.dropped) {
        toast('dropped ' + url);
        const row = document.querySelector('#proxyTable tbody tr[data-url="' + escapeSelector(url) + '"]');
        if (row) row.remove();
        listed = listed.filter((p) => p.url !== url);
      } else {
        toast('already gone: ' + url);
        loadProxies();
      }
    } catch (e) { toast(e.message, true); b.disabled = false; }
  };
  return b;
}

function copyButton(url) {
  const b = el('button', 'copy', 'copy');
  b.title = 'Copy the curl command (right-click for wget)';
  const curl = 'curl -x ' + url + ' https://httpbin.org/ip';
  const wget = 'wget -e use_proxy=yes -e https_proxy=' + url + ' https://httpbin.org/ip';
  b.onclick = () => navigator.clipboard.writeText(curl).then(() => toast('Copied: ' + curl));
  b.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    navigator.clipboard.writeText(wget).then(() => toast('Copied wget: ' + wget));
  });
  return b;
}

function renderProxies(proxies) {
  const tb = $('#proxyTable tbody');
  tb.replaceChildren();
  listed = proxies || [];
  for (const p of listed) {
    const row = tr(proxyCells(p));
    row.dataset.url = p.url;
    tb.append(row);
  }
  // Do not touch #proxyCount here: loadProxies writes the richer "N best of
  // M in scope" line, and this render (also driven by WS state) used to
  // clobber it with "N in scope" so the total never reached the user.
}

function applyProxiesDelta(added, removed, updated) {
  const tb = $('#proxyTable tbody');
  for (var i = 0; i < removed.length; i++) {
    var row = document.querySelector('#proxyTable tbody tr[data-url="' + escapeSelector(removed[i]) + '"]');
    if (row) row.remove();
    listed = listed.filter((p) => p.url !== removed[i]);
  }
  var byUrl = {};
  for (const p of listed) byUrl[p.url] = p;
  var changed = added.concat(updated);
  for (var j = 0; j < changed.length; j++) {
    const p = changed[j];
    if (byUrl[p.url]) Object.assign(byUrl[p.url], p);
    else { listed.push(p); byUrl[p.url] = p; }
    let row = document.querySelector('#proxyTable tbody tr[data-url="' + escapeSelector(p.url) + '"]');
    const cells = proxyCells(p);
    if (row) {
      row.replaceChildren.apply(row, cells.map(function (c, i) {
        var td = el('td');
        if (c && c.nodeType) td.append(c); else td.textContent = String(c);
        return td;
      }));
    } else {
      row = tr(cells);
      row.dataset.url = p.url;
      tb.append(row);
    }
  }
}

async function loadSources() {
  const d = await get('/api/sources');
  renderSources(d.sources);
}

async function loadSites() {
  const d = await get('/api/sites');
  $('#sitePath').textContent = d.path;
  $('#siteCount').textContent = num(d.entries.length) + ' entries, ' +
    d.comments + ' comment lines, ' + d.path;
  const tb = $('#siteTable tbody');
  tb.replaceChildren();
  d.entries.forEach((u, i) => {
    const del = el('button', 'remove', '');
    del.onclick = async () => {
      if (!confirm('Remove ' + u + ' from ' + d.path + '?')) return;
      try {
        const j = await post('DELETE', '/api/sites', { url: u });
        toast(j.changed ? 'removed ' + u : 'not in the list: ' + u);
        loadSites();
      } catch (e) { toast(e.message, true); }
    };
    tb.append(tr([String(i + 1), u, del]));
  });
}

// loadLogs shows the in-memory tail of one log category: the same lines
// that land in data/logs/*.log. Category files rotate; this tail does not.
async function loadLogs() {
  const cat = $('#logCategory').value;
  const d = await get('/api/logs?category=' + encodeURIComponent(cat) + '&limit=200');
  const lines = d.lines || [];
  $('#logCount').textContent = num(lines.length) + ' recent lines — ' + cat;
  $('#logTail').textContent = lines.join('\n') || '(empty)';
}

function renderSources(sources) {
  $('#sourceCount').textContent =
    num(sources.filter(s => s.alive > 0).length) + ' of ' + num(sources.filter(s => !s.unproven).length) +
    ' measured sources still produce live proxies (' + num(sources.length) + ' tracked)';
  const tb = $('#sourceTable tbody');
  tb.replaceChildren();
  for (const s of sources) {
    let state, cls;
    if (s.unproven) { state = 'not fetched yet'; cls = 'muted'; }
    else if (s.cooling) { state = 'cooling until ' + (s.cool_until || '').slice(11, 19); cls = 'bad'; }
    else if (s.ok) { state = 'ok'; cls = 'ok'; }
    else { state = 'failing'; cls = 'warn'; }
    const retry = el('button', 'retry now', '');
    retry.title = 'Clear the failure cooldown so the next cycle fetches this source in full';
    retry.onclick = async () => {
      try {
        await post('POST', '/api/sources/cooldown', { url: s.url });
        toast('cooldown cleared for ' + s.url);
        loadSources();
      } catch (e) { toast(e.message, true); }
    };
    tb.append(tr([
      s.url, num(s.alive),
      s.unproven ? '-' : s.yield_pct.toFixed(1) + '%',
      num(s.emitted), num(s.found), num(s.cycles), num(s.fails),
      el('span', state, 'tag ' + cls), s.last_note || '-',
      retry,
    ]));
  }
}

// --- 24h history chart ---------------------------------------------------

const series = [
  { key: 'queue_live', label: 'queue live', color: '#4c8dff' },
  { key: 'queue_hot', label: 'queue hot', color: '#35c98b' },
  { key: 'pool_candidates', label: 'pool candidates', color: '#e2b23c' },
];

// Rate series share the samples but not the scale: requests/min next to a
// 50k queue would be a flat line at zero on the left axis. They get the
// right axis, dashed. These are the numbers the hint talks about — sizes
// say how big the pool is, rates say whether it is getting better or worse.
const rateSeries = [
  { key: 'requests_per_min', label: 'req/min', color: '#b48cff' },
  { key: 'dial_fail_per_min', label: 'dialfail/min', color: '#e2603f' },
];

async function loadGraph() {
  const d = await get('/api/stats/history');
  const samples = d.samples || [];
  $('#graphCount').textContent = samples.length
    ? num(samples.length) + ' samples, ' + samples[0].time.slice(0, 16) + ' to ' +
      samples[samples.length - 1].time.slice(0, 16)
    : 'no samples yet (one per minute)';
  drawChart(samples);
  $('#chartLegend').replaceChildren(...series.map((s) => {
    const item = el('span');
    const dot = el('i');
    dot.style.background = s.color;
    item.append(dot, document.createTextNode(s.label));
    return item;
  }).concat(rateSeries.map((s) => {
    const item = el('span');
    const dot = el('i');
    dot.style.background = s.color;
    dot.style.height = '0';
    dot.style.borderTop = '2px dashed ' + s.color;
    item.append(dot, document.createTextNode(s.label + ' (right)'));
    return item;
  })));
}

// drawChart renders the queue-size series as polylines. Four series over a
// canvas by hand keeps the page asset-free; a charting library is more than
// this panel is worth.
function drawChart(samples) {
  const cv = $('#chart');
  const ctx = cv.getContext('2d');
  const w = cv.width, h = cv.height, pad = 8, rpad = 52;
  ctx.clearRect(0, 0, w, h);
  if (!samples.length) return;
  let max = 1, maxRate = 1;
  for (const s of samples) {
    for (const ser of series) {
      const v = s[ser.key] || 0;
      if (v > max) max = v;
    }
    for (const ser of rateSeries) {
      const v = s[ser.key] || 0;
      if (v > maxRate) maxRate = v;
    }
  }
  const x = (i) => pad + (i * (w - pad - rpad)) / Math.max(1, samples.length - 1);
  const y = (v) => h - pad - (v * (h - 2 * pad)) / max;
  const yRate = (v) => h - pad - (v * (h - 2 * pad)) / maxRate;
  // Grid: 4 horizontal lines with their values.
  ctx.strokeStyle = '#262b36';
  ctx.fillStyle = '#8b93a3';
  ctx.font = '11px monospace';
  for (let g = 0; g <= 4; g++) {
    const v = (max * g) / 4, yy = y(v);
    ctx.beginPath(); ctx.moveTo(pad, yy); ctx.lineTo(w - rpad, yy); ctx.stroke();
    ctx.fillText(Math.round(v).toLocaleString(), w - rpad - 46, yy - 3);
    // Right axis: the rate scale, so req/min and dialfail/min stay readable
    // next to queue sizes thousands of times larger.
    const rv = (maxRate * g) / 4;
    ctx.fillText(Math.round(rv).toLocaleString(), w - rpad + 6, yy - 3);
  }
  for (const ser of series) {
    ctx.strokeStyle = ser.color;
    ctx.lineWidth = 2;
    ctx.setLineDash([]);
    ctx.beginPath();
    samples.forEach((s, i) => {
      const yy = y(s[ser.key] || 0);
      if (i === 0) ctx.moveTo(x(i), yy); else ctx.lineTo(x(i), yy);
    });
    ctx.stroke();
  }
  for (const ser of rateSeries) {
    ctx.strokeStyle = ser.color;
    ctx.lineWidth = 2;
    ctx.setLineDash([6, 4]);
    ctx.beginPath();
    samples.forEach((s, i) => {
      const yy = yRate(s[ser.key] || 0);
      if (i === 0) ctx.moveTo(x(i), yy); else ctx.lineTo(x(i), yy);
    });
    ctx.stroke();
  }
  ctx.setLineDash([]);
}

function currentTab() {
  return document.querySelector('.tab.active').dataset.tab;
}

function refresh() {
  const jobs = [loadHealth(),
    currentTab() === 'proxies' ? loadProxies() : Promise.resolve(),
    currentTab() === 'sources' ? loadSources() : Promise.resolve(),
    currentTab() === 'graph' ? loadGraph() : Promise.resolve(),
    currentTab() === 'sites' ? loadSites() : Promise.resolve(),
    currentTab() === 'logs' ? loadLogs() : Promise.resolve()];
  Promise.all(jobs).catch((e) => toast(e.message || String(e), true));
}

$('#scope').onchange = loadProxies;
$('#country').onchange = loadProxies;
$('#asn').onchange = loadProxies;
$('#logCategory').onchange = loadLogs;
$('#refresh').onclick = () => refresh();
// The add-sites form used to have no handler at all: the native GET submit
// reloaded the page (landing back on the default tab) and the paste never
// reached the API — every "add" silently did nothing.
$('#addForm').onsubmit = async (e) => {
  e.preventDefault();
  const box = $('#siteUrls');
  const lines = box.value.split('\n').map((s) => s.trim()).filter((s) => s !== '');
  if (!lines.length) { toast('paste at least one URL', true); box.focus(); return; }
  try {
    const j = await post('POST', '/api/sites', { urls: lines });
    const parts = [];
    if (j.added) parts.push('added ' + j.added);
    if (j.duplicates) parts.push(j.duplicates + ' duplicate' + (j.duplicates > 1 ? 's' : '') + ' skipped');
    if (j.invalid && j.invalid.length) parts.push(j.invalid.length + ' invalid: ' +
      j.invalid.map((x) => x.line).join(', '));
    toast(parts.join(', ') || 'nothing to add');
    if (j.added) box.value = '';
    loadSites(); // no reload: the view stays on the sites tab
  } catch (err) { toast(err.message, true); }
};
$('#wake').onclick = async () => {
  try {
    const j = await post('POST', '/api/collector/wake', {});
    toast(j.note || 'collector woken');
  } catch (e) { toast(e.message, true); }
};
$('#shutdown').onclick = async () => {
  if (!confirm('Shut down protator now? It drains requests, saves the queue and flushes the pool first.')) return;
  try {
    const j = await post('POST', '/api/shutdown', {});
    toast(j.note || 'shutting down');
  } catch (e) { toast(e.message, true); }
};
$('#retestShown').onclick = async () => {
  if (!listed.length) { toast('nothing listed'); return; }
  const urls = listed.map((p) => p.url).slice(0, 500);
  try {
    const j = await post('POST', '/api/proxies/revalidate', { urls });
    toast('re-checking ' + (j.revalidated || 0) + ' of ' + urls.length + ' listed');
  } catch (e) { toast(e.message, true); }
};

document.querySelectorAll('.tab').forEach((t) => {
  t.onclick = () => {
    document.querySelectorAll('.tab').forEach((x) => x.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((x) => x.classList.remove('active'));
    t.classList.add('active');
    $('#' + t.dataset.tab).classList.add('active');
    if (t.dataset.tab === 'graph') loadGraph();
    if (t.dataset.tab === 'logs') loadLogs();
  };
});

// WebSocket connection for live updates
let ws = null;
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  let url = proto + '//' + location.host + '/ws';
  if (TOKEN) url += '?token=' + encodeURIComponent(TOKEN);
  ws = new WebSocket(url);
  ws.onopen = () => console.log('WS connected');
  ws.onclose = () => { console.log('WS closed, reconnecting...'); setTimeout(connectWS, 2000); };
  ws.onerror = (e) => console.error('WS error', e);
  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      // 'delta' is what the server actually broadcasts (adminws.go); the old
      // gate only accepted 'state'/'update' — 'update' is never sent — so
      // every delta was parsed and discarded and the live table only changed
      // on the 30s HTTP poll.
      if (msg.type === 'state' || msg.type === 'update' || msg.type === 'delta') {
        applyWSMessage(msg);
      }
    } catch (e) { console.error('WS parse error', e); }
  };
}

function applyWSMessage(msg) {
  if (msg.health) {
    renderTiles(msg.health);
  }
  // Handle delta updates (type "delta") - incremental changes
  if (msg.type === 'delta') {
    if (currentTab() === 'proxies') {
      applyProxiesDelta(msg.added || [], msg.removed || [], msg.updated || []);
    }
    return;
  }
  if (msg.type === 'state') {
    if (msg.proxies && currentTab() === 'proxies') renderProxies(msg.proxies);
    if (msg.sources && currentTab() === 'sources') renderSources(msg.sources);
  }
}

function escapeSelector(s) {
  return s.replace(/[!"#$%&'()*+,.\/:;<=>?@[\\\]^\x60{|}~]/g, '\\$&');
}

// Initialize WebSocket on load
connectWS();
// Keep periodic refresh as fallback (30s)
setInterval(refresh, 30000);

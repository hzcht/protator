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
  if (q) { TOKEN = q; localStorage.setItem('protator_token', q); }
  else { TOKEN = localStorage.getItem('protator_token') || null; }
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

function tile(k, v) {
  const t = el('div', undefined, 'tile');
  t.append(el('span', k, 'k'), el('span', String(v), 'v'));
  return t;
}

async function loadHealth() {
  const h = await get('/health');
  const tiles = $('#tiles');
  tiles.replaceChildren(
    tile('live', num(h.queue_live)),
    tile('proven', num(h.queue_proven)),
    tile('hot', num(h.queue_hot)),
    tile('pool', num(h.pool_candidates)),
    tile('served', num(h.served_ok_total)),
    tile('dialfail', num(h.dial_failures_total)),
    tile('checks', num(h.checks_total)),
    tile('uptime', Math.floor(h.uptime_seconds / 60) + 'm'),
    tile('tls', h.tls ? 'yes' : 'no'),
  );
  $('#wake').disabled = !!h.beats && h.beats.collector_stale;
  $('#wake').title = h.beats && h.beats.collector_stale
    ? 'Collector has not run a cycle recently - collecting now is the fix'
    : 'Force a collector cycle now (the site list is re-read)';
}

// loadProxies fetches initial proxies via HTTP (fallback before WS connects)
async function loadProxies() {
  const scope = $('#scope').value;
  const country = $('#country').value.trim();
  let url = '/api/proxies?scope=' + encodeURIComponent(scope) + '&limit=' + pageSize;
  if (country) url += '&country=' + encodeURIComponent(country);
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
  ];
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
  $('#proxyCount').textContent = listed.length + ' in scope';
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
  }));
}

// drawChart renders the queue-size series as polylines. Four series over a
// canvas by hand keeps the page asset-free; a charting library is more than
// this panel is worth.
function drawChart(samples) {
  const cv = $('#chart');
  const ctx = cv.getContext('2d');
  const w = cv.width, h = cv.height, pad = 8;
  ctx.clearRect(0, 0, w, h);
  if (!samples.length) return;
  let max = 1;
  for (const s of samples) {
    for (const ser of series) {
      const v = s[ser.key] || 0;
      if (v > max) max = v;
    }
  }
  const x = (i) => pad + (i * (w - 2 * pad)) / Math.max(1, samples.length - 1);
  const y = (v) => h - pad - (v * (h - 2 * pad)) / max;
  // Grid: 4 horizontal lines with their values.
  ctx.strokeStyle = '#262b36';
  ctx.fillStyle = '#8b93a3';
  ctx.font = '11px monospace';
  for (let g = 0; g <= 4; g++) {
    const v = (max * g) / 4, yy = y(v);
    ctx.beginPath(); ctx.moveTo(pad, yy); ctx.lineTo(w - pad, yy); ctx.stroke();
    ctx.fillText(Math.round(v).toLocaleString(), w - pad - 46, yy - 3);
  }
  for (const ser of series) {
    ctx.strokeStyle = ser.color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    samples.forEach((s, i) => {
      const yy = y(s[ser.key] || 0);
      if (i === 0) ctx.moveTo(x(i), yy); else ctx.lineTo(x(i), yy);
    });
    ctx.stroke();
  }
}

function currentTab() {
  return document.querySelector('.tab.active').dataset.tab;
}

function refresh() {
  const jobs = [loadHealth(),
    currentTab() === 'proxies' ? loadProxies() : Promise.resolve(),
    currentTab() === 'sources' ? loadSources() : Promise.resolve(),
    currentTab() === 'graph' ? loadGraph() : Promise.resolve(),
    currentTab() === 'sites' ? loadSites() : Promise.resolve()];
  Promise.all(jobs).catch((e) => toast(e.message || String(e), true));
}

$('#scope').onchange = loadProxies;
$('#refresh').onclick = () => refresh();
$('#wake').onclick = async () => {
  try {
    const j = await post('POST', '/api/collector/wake', {});
    toast(j.note || 'collector woken');
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
      if (msg.type === 'state' || msg.type === 'update') {
        applyWSMessage(msg);
      }
    } catch (e) { console.error('WS parse error', e); }
  };
}

function applyWSMessage(msg) {
  if (msg.health) {
    const h = msg.health;
    const tiles = $('#tiles');
    tiles.replaceChildren(
      tile('live', num(h.queue_live)),
      tile('proven', num(h.queue_proven)),
      tile('hot', num(h.queue_hot)),
      tile('pool', num(h.pool_candidates)),
      tile('served', num(h.served_ok_total)),
      tile('dialfail', num(h.dial_failures_total)),
      tile('checks', num(h.checks_total)),
      tile('uptime', Math.floor(h.uptime_seconds / 60) + 'm'),
      tile('tls', h.tls ? 'yes' : 'no'),
    );
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

package main

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>protator admin</title>
<link rel="stylesheet" href="/static/admin.css">
</head>
<body>
<header>
  <h1>protator</h1>
  <div id="tiles" class="tiles"></div>
  <button id="refresh" type="button">Refresh</button>
</header>

<nav class="tabs">
  <button class="tab active" data-tab="proxies" type="button">Live proxies</button>
  <button class="tab" data-tab="sources" type="button">Sources</button>
  <button class="tab" data-tab="sites" type="button">sites.txt</button>
</nav>

<section id="proxies" class="panel active">
  <div class="bar">
    <label>Definition
      <select id="scope">
        <option value="hot" selected>hot tail (best evidence)</option>
        <option value="served">served traffic</option>
        <option value="checked">validated recently</option>
        <option value="all">whole queue</option>
      </select>
    </label>
    <span id="proxyCount" class="muted"></span>
    <a id="download" class="button" href="/api/proxies?format=text">Download .txt</a>
  </div>
  <p class="hint">Four definitions, from strongest evidence to weakest:
    <b>hot tail</b> is the curated set the picker samples, so it is what is
    working right now; <b>served traffic</b> is the strict subset that carried a
    real client request in the window; <b>validated recently</b> adds proxies
    that only passed a check; <b>whole queue</b> also lists unproven entries,
    which is a diagnostic view, not a list to use.</p>
  <table id="proxyTable">
    <thead><tr>
      <th>proxy</th><th>schema</th><th>latency</th><th>ok/fail</th>
      <th>proof age</th><th>proof</th><th>source</th><th></th>
    </tr></thead>
    <tbody></tbody>
  </table>
</section>

<section id="sources" class="panel">
  <div class="bar">
    <span id="sourceCount" class="muted"></span>
  </div>
  <p class="hint">Every entry of sites.txt with the verdict of the checker on
    what it produced. Yield is the share of that source's candidates still
    alive; it is the number that decides whether a source earns its place.
    The collector fetches the highest-priority sources first, so a source at
    the top is one that recently delivered working proxies.</p>
  <table id="sourceTable">
    <thead><tr>
      <th>source</th><th>alive</th><th>yield</th><th>emitted</th>
      <th>found</th><th>cycles</th><th>fails</th><th>state</th><th>last note</th>
    </tr></thead>
    <tbody></tbody>
  </table>
</section>

<section id="sites" class="panel">
  <div class="bar">
    <span id="siteCount" class="muted"></span>
    <form id="addForm" class="inline">
      <input id="siteUrl" type="text" placeholder="https://example.com/proxy-list.txt" size="52" spellcheck="false">
      <button type="submit">Add</button>
    </form>
  </div>
  <p class="hint">Edits are written to <code id="sitePath"></code> atomically,
    with the previous contents kept as <code>.bak</code>. The collector re-reads
    the file at the start of every cycle, so a change takes effect then; there
    is no restart. The list is never allowed to become empty.</p>
  <table id="siteTable">
    <thead><tr><th>#</th><th>url</th><th></th></tr></thead>
    <tbody></tbody>
  </table>
</section>

<div id="toast" class="toast"></div>
<script src="/static/admin.js"></script>
</body>
</html>
`

const adminCSS = `:root {
  --bg: #0f1115; --panel: #171a21; --line: #262b36; --fg: #dfe3ea;
  --muted: #8b93a3; --accent: #4c8dff; --ok: #35c98b; --warn: #e2b23c; --bad: #e2603f;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
header {
  display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
  padding: 14px 20px; border-bottom: 1px solid var(--line); background: var(--panel);
}
h1 { margin: 0; font-size: 18px; letter-spacing: .5px; color: var(--accent); }
.tiles { display: flex; gap: 10px; flex-wrap: wrap; flex: 1; }
.tile {
  background: #11141a; border: 1px solid var(--line); border-radius: 6px;
  padding: 6px 12px; min-width: 92px;
}
.tile .k { display: block; color: var(--muted); font-size: 11px; text-transform: uppercase; }
.tile .v { display: block; font-size: 18px; }
button, .button {
  background: #1d222c; color: var(--fg); border: 1px solid var(--line);
  border-radius: 6px; padding: 7px 12px; cursor: pointer; font: inherit;
  text-decoration: none; display: inline-block;
}
button:hover, .button:hover { border-color: var(--accent); }
.tabs { display: flex; gap: 6px; padding: 12px 20px 0; }
.tab.active { border-color: var(--accent); color: var(--accent); }
.panel { display: none; padding: 12px 20px 40px; }
.panel.active { display: block; }
.bar { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; margin-bottom: 8px; }
.inline { display: flex; gap: 6px; }
input[type=text], select {
  background: #11141a; color: var(--fg); border: 1px solid var(--line);
  border-radius: 6px; padding: 7px 9px; font: inherit;
}
.hint { color: var(--muted); margin: 4px 0 12px; max-width: 100ch; }
.muted { color: var(--muted); }
table { width: 100%; border-collapse: collapse; }
th, td {
  text-align: left; padding: 5px 8px; border-bottom: 1px solid var(--line);
  vertical-align: top; word-break: break-all;
}
th { color: var(--muted); font-weight: 500; font-size: 12px; text-transform: uppercase; }
tbody tr:hover { background: #14181f; }
.tag { border-radius: 4px; padding: 1px 6px; font-size: 12px; }
.ok { color: var(--ok); } .warn { color: var(--warn); } .bad { color: var(--bad); }
code { color: var(--accent); }
.copy { background: transparent; border: none; color: var(--muted); cursor: pointer; padding: 2px 6px; font-size: 14px; border-radius: 4px; }
.copy:hover { color: var(--accent); background: var(--line); }
.toast {
  position: fixed; right: 16px; bottom: 16px; max-width: 60ch;
  background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--accent);
  border-radius: 6px; padding: 10px 14px; opacity: 0; pointer-events: none;
  transition: opacity .2s;
}
.toast.show { opacity: 1; }
.toast.err { border-left-color: var(--bad); }
`

const adminJS = `const $ = (s) => document.querySelector(s);
const pageSize = 1000;
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

async function get(url) {
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) throw new Error(url + ' -> HTTP ' + r.status);
  return r.json();
}

async function post(method, url, payload) {
  const r = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
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
    tile('hot', num(h.queue_hot)),
    tile('pool', num(h.pool_candidates)),
    tile('uptime', Math.floor(h.uptime_seconds / 60) + 'm'),
    tile('tls', h.tls ? 'yes' : 'no'),
  );
}

// loadProxies fetches initial proxies via HTTP (fallback before WS connects)
async function loadProxies() {
  const scope = $('#scope').value;
  const d = await get('/api/proxies?scope=' + encodeURIComponent(scope) + '&limit=' + pageSize);
  $('#proxyCount').textContent = d.total > d.count
    ? num(d.count) + ' best of ' + num(d.total) + ' in scope (window ' +
      Math.round(d.window_seconds / 60) + ' min)'
    : num(d.count) + ' in scope, window ' + Math.round(d.window_seconds / 60) + ' min';
  $('#download').href = '/api/proxies?scope=' + encodeURIComponent(scope) + '&format=text';
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

$('#addForm').onsubmit = async (ev) => {
  ev.preventDefault();
  const input = $('#siteUrl');
  const url = input.value.trim();
  if (!url) return;
  try {
    const j = await post('POST', '/api/sites', { url });
    toast(j.added ? 'added ' + url + ' - ' + j.note : 'already in the list: ' + url);
    input.value = '';
    loadSites();
  } catch (e) { toast(e.message, true); }
};

$('#scope').onchange = loadProxies;
$('#refresh').onclick = () => refresh();

document.querySelectorAll('.tab').forEach((t) => {
  t.onclick = () => {
    document.querySelectorAll('.tab').forEach((x) => x.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((x) => x.classList.remove('active'));
    t.classList.add('active');
    $('#' + t.dataset.tab).classList.add('active');
  };
});

// WebSocket connection for live updates
let ws = null;
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(proto + '//' + location.host + '/ws');
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
  // Update health tiles
  if (msg.health) {
    const h = msg.health;
    const tiles = $('#tiles');
    tiles.replaceChildren(
      tile('live', num(h.queue_live)),
      tile('hot', num(h.queue_hot)),
      tile('pool', num(h.pool_candidates)),
      tile('uptime', Math.floor(h.uptime_seconds / 60) + 'm'),
      tile('tls', h.tls ? 'yes' : 'no'),
    );
  }
  // Handle delta updates (type "delta") - incremental changes
  if (msg.type === 'delta') {
    const scope = $('#scope').value;
    if (document.querySelector('.tab.active').dataset.tab === 'proxies') {
      applyProxiesDelta(msg.added, msg.removed, msg.updated);
    }
    return;
  }
  // Full state updates (type "state" or "update")
  if (msg.type === 'state' || msg.type === 'update') {
    if (msg.proxies && document.querySelector('.tab.active').dataset.tab === 'proxies') {
      renderProxies(msg.proxies);
    }
  }
  // Update history if on proxies tab (optional)
  // Update sources if on sources tab
  if (msg.sources && document.querySelector('.tab.active').dataset.tab === 'sources') {
    renderSources(msg.sources);
  }
}

function applyProxiesDelta(added, removed, updated) {
  const tb = $('#proxyTable tbody');
  // Remove rows for removed proxies
  for (var i = 0; i < removed.length; i++) {
    var url = removed[i];
    var sel = '#proxyTable tbody tr[data-url="' + escapeSelector(url) + '"]';
    var row = document.querySelector(sel);
    if (row) row.remove();
  }
  // Update or add rows for updated/added proxies
  var combined = added.concat(updated);
  for (var j = 0; j < combined.length; j++) {
    var p = combined[j];
    var sel = '#proxyTable tbody tr[data-url="' + escapeSelector(p.url) + '"]';
    var existingRow = document.querySelector(sel);
    var proof = p.served ? 'served' : (p.checked ? 'validated' : 'queued');
    var cls = p.served ? 'ok' : (p.checked ? 'warn' : 'muted');
    var curlCmd = 'curl -x ' + p.url + ' https://httpbin.org/ip';
    var wgetCmd = 'wget -e use_proxy=yes -e https_proxy=' + p.url + ' https://httpbin.org/ip';
    var copyBtn = el('button', 'copy', 'copy');
    copyBtn.title = 'Copy curl/wget command';
    copyBtn.onclick = function() {
      navigator.clipboard.writeText(curlCmd).then(function() { toast('Copied: ' + curlCmd); });
    };
    copyBtn.addEventListener('contextmenu', function(e) {
      e.preventDefault();
      navigator.clipboard.writeText(wgetCmd).then(function() { toast('Copied wget: ' + wgetCmd); });
    });
    var cells = [
      p.url, p.schema || '-', p.latency_ms + ' ms',
      p.ok_total + '/' + p.fail_total,
      Math.round(p.proof_age_s) + ' s',
      el('span', proof, 'tag ' + cls),
      p.source || '-',
      copyBtn,
    ];
    if (existingRow) {
      // Update existing row
      existingRow.replaceChildren.apply(existingRow, cells.map(function(c, i) {
        var td = el('td');
        if (c && c.nodeType) td.append(c); else td.textContent = String(c);
        return td;
      }));
      existingRow.dataset.url = p.url;
    } else {
      // Add new row
      const row = tr(cells);
      row.dataset.url = p.url;
      tb.append(row);
    }
  }
}

function escapeSelector(s) {
  return s.replace(/[!"#$%&'()*+,.\/:;<=>?@[\\\]^\x60{|}~]/g, '\\$&');
}

function renderProxies(proxies) {
  const scope = $('#scope').value;
  const tb = $('#proxyTable tbody');
  tb.replaceChildren();
  for (const p of proxies) {
    const proof = p.served ? 'served' : (p.checked ? 'validated' : 'queued');
    const cls = p.served ? 'ok' : (p.checked ? 'warn' : 'muted');
    const curlCmd = 'curl -x ' + p.url + ' https://httpbin.org/ip';
    const wgetCmd = 'wget -e use_proxy=yes -e https_proxy=' + p.url + ' https://httpbin.org/ip';
    const copyBtn = el('button', 'copy', 'copy');
    copyBtn.title = 'Copy curl/wget command';
    copyBtn.onclick = () => {
      navigator.clipboard.writeText(curlCmd).then(() => toast('Copied: ' + curlCmd));
    };
    copyBtn.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      navigator.clipboard.writeText(wgetCmd).then(() => toast('Copied wget: ' + wgetCmd));
    });
    tb.append(tr([
      p.url, p.schema || '-', p.latency_ms + ' ms',
      p.ok_total + '/' + p.fail_total,
      Math.round(p.proof_age_s) + ' s',
      el('span', proof, 'tag ' + cls),
      p.source || '-',
      copyBtn,
    ]));
  }
  $('#proxyCount').textContent = proxies.length + ' in scope';
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
    tb.append(tr([
      s.url, num(s.alive),
      s.unproven ? '-' : s.yield_pct.toFixed(1) + '%',
      num(s.emitted), num(s.found), num(s.cycles), num(s.fails),
      el('span', state, 'tag ' + cls), s.last_note || '-',
    ]));
  }
}

function refresh() {
  // Fallback for initial load or if WS not connected
  const tab = document.querySelector('.tab.active').dataset.tab;
  const jobs = [loadHealth(),
    tab === 'proxies' ? loadProxies() : Promise.resolve(),
    tab === 'sources' ? loadSources() : Promise.resolve(),
    tab === 'sites' ? loadSites() : Promise.resolve()];
  Promise.all(jobs).catch((e) => toast(e.message || String(e), true));
}

// Initialize WebSocket on load
connectWS();
// Keep periodic refresh as fallback (30s)
setInterval(refresh, 30000);
`

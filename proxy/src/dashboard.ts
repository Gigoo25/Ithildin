// The local dashboard: one page, polling /dashboard/activity (events.ts).
// It is a string in a module because the package copies only src/*.ts.
//
// Every value on the page reaches the DOM through textContent. Stand-ins, tool
// names and guard notices come from content the proxy does not control, so
// none of it is ever parsed as HTML.

export const DASHBOARD_PATH = "/dashboard";
export const ACTIVITY_PATH = "/dashboard/activity";
export const REQUESTS_PATH = "/dashboard/requests";
export const REQUEST_PATH = "/dashboard/request";

// No network but this origin, and no markup from anywhere else.
export const DASHBOARD_CSP =
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
  "img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'";

// A crescent moon and a star on the page's dark blue. Inline, so the browser
// never asks the proxy for /favicon.ico, which it would refuse and log.
const FAVICON_SVG =
  "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>" +
  "<rect width='64' height='64' rx='12' fill='#1d2432'/>" +
  "<mask id='cut'><rect width='64' height='64' fill='#fff'/>" +
  "<circle cx='36' cy='36' r='15' fill='#000'/></mask>" +
  "<circle cx='27' cy='38' r='19' fill='#d3dcea' mask='url(#cut)'/>" +
  "<polygon points='" +
  "46.0,9.0 47.6,16.1 53.8,12.2 49.9,18.4 " +
  "57.0,20.0 49.9,21.6 53.8,27.8 47.6,23.9 " +
  "46.0,31.0 44.4,23.9 38.2,27.8 42.1,21.6 " +
  "35.0,20.0 42.1,18.4 38.2,12.2 44.4,16.1" +
  "' fill='#d3dcea'/></svg>";
const FAVICON = "data:image/svg+xml," + encodeURIComponent(FAVICON_SVG);
// The same, with a red mark: the tab shows it while a leak has been found.
const FAVICON_ALERT =
  "data:image/svg+xml," +
  encodeURIComponent(
    FAVICON_SVG.replace(
      "</svg>",
      "<circle cx='50' cy='50' r='12' fill='#ff6b5e' stroke='#1d2432' stroke-width='3'/></svg>",
    ),
  );

export const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ithildin</title>
<link id="icon" rel="icon" href="${FAVICON}">
<style>
  :root {
    color-scheme: dark light;
    --bg: #1d2432; --panel: #252e40; --head: #212a3a; --edge: #3c485e; --soft: #ffffff14;
    --ink: #e9eef6; --dim: #aab5c7; --silver: #d3dcea;
    --masked: #8fb8ff; --masked_bg: #8fb8ff26;
    --swapped: #7fd9b9; --swapped_bg: #7fd9b926;
    --alert: #ff9d8c; --alert_bg: #ff9d8c26;
    --quiet: #c5cedc; --quiet_bg: #ffffff1a;
    --serif: Palatino, 'Palatino Linotype', 'Book Antiqua', Georgia, serif;
  }
  /* In daylight the door is a blank cliff face: plain stone. */
  @media (prefers-color-scheme: light) {
    :root {
      --bg: #ebe9e4; --panel: #f6f5f1; --head: #e4e1da; --edge: #0000002e; --soft: #0000001a;
      --ink: #292826; --dim: #5a5750; --silver: #4a4843;
      --masked: #17469a; --masked_bg: #17469a1f;
      --swapped: #0b5f4a; --swapped_bg: #0b5f4a1f;
      --alert: #962718; --alert_bg: #9627181f;
      --quiet: #44413b; --quiet_bg: #0000001a;
    }
  }
  body {
    font: 14px/1.45 system-ui, sans-serif; color: var(--ink); background: var(--bg);
    margin: 0 auto; max-width: 1400px; padding: 10px 20px 14px; box-sizing: border-box;
    height: 100vh; display: flex; flex-direction: column;
  }
  header { display: flex; justify-content: center; align-items: center; gap: 28px; }
  .door { display: block; width: 175px; height: auto; color: var(--silver); flex: none; }
  .title { text-align: left; }
  h1 {
    font: 600 26px/1.1 var(--serif); letter-spacing: .45em;
    text-transform: uppercase; margin: 0 0 4px; color: var(--silver);
  }
  .motto { font: italic 15px var(--serif); color: var(--dim); margin: 0 0 6px; }
  #state { font-weight: 600; letter-spacing: .05em; }
  #state.down { color: var(--alert); }
  #state.up { color: var(--swapped); }
  h2 {
    display: flex; align-items: center; gap: 12px; margin: 14px 0 8px;
    font: 600 14px var(--serif); letter-spacing: .2em; text-transform: uppercase;
    color: var(--silver);
  }
  h2::after { content: ''; flex: 1; border-top: 1px solid var(--edge); }
  #tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 8px; }
  .tile { border: 1px solid var(--edge); border-radius: 4px; padding: 6px 10px; }
  .tile { background: var(--panel); }
  .tile b { display: block; font: 600 21px/1.2 var(--serif); color: var(--silver); }
  .tile span { color: var(--dim); font-size: 12px; line-height: 1.25; display: block; }
  #kinds {
    display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 10px;
    color: var(--dim);
  }
  .chip {
    border: 1px solid var(--edge); border-radius: 999px; padding: 1px 10px;
    background: var(--panel); color: var(--ink);
  }
  .chip b { color: var(--silver); margin-left: 4px; }
  .scroll {
    overflow-x: auto; border: 1px solid var(--edge); border-radius: 4px;
    background: var(--panel);
  }
  /* A long history scrolls inside its box; the header row stays in view. */
  .tall { flex: 1; min-height: 180px; overflow-y: auto; }
  .activity { flex: 1; min-height: 0; display: flex; flex-direction: column; }
  .bar { display: flex; justify-content: space-between; align-items: baseline; gap: 16px; }
  /* One entry: the message first, then what the proxy knows about it, dimmed. */
  .entry { padding: 9px 14px 8px; border-bottom: 1px solid var(--soft); }
  .entry.leak_row { background: var(--alert_bg); }
  .msg {
    font: 13px/1.5 ui-monospace, monospace; white-space: pre-wrap; overflow-wrap: anywhere;
  }
  .msg.plain { font-family: system-ui, sans-serif; }
  .msg mark, #viewer mark {
    background: var(--masked_bg); color: var(--ink); outline: 1px solid var(--masked);
    border-radius: 2px; padding: 0 1px;
  }
  .msg mark[data-part=other] { background: none; outline-style: dotted; opacity: .75; }
  .msg mark[data-type=swapped] { background: var(--swapped_bg); outline-color: var(--swapped); }
  .meta {
    display: flex; flex-wrap: wrap; align-items: center; gap: 4px 10px; margin-top: 5px;
    font-size: 12px; color: var(--dim);
  }
  .meta > span:not(.tag) { opacity: .7; }
  .meta .when { margin-left: auto; }
  .tag { border-radius: 3px; padding: 1px 7px; font-size: 11px; font-weight: 600; }
  .masked { background: var(--masked_bg); color: var(--masked); }
  .swapped { background: var(--swapped_bg); color: var(--swapped); }
  .blocked, .refused, .leaked { background: var(--alert_bg); color: var(--alert); }
  .tile.alarm { border-color: var(--alert); }
  .tile.alarm b { color: var(--alert); }
  .request { background: var(--quiet_bg); color: var(--quiet); }
  #filters { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 8px; color: var(--dim); }
  .empty { color: var(--dim); font-style: italic; padding: 10px; }
  .count { color: var(--dim); font-size: 12px; margin: 0 0 8px; }
  [hidden] { display: none !important; }
  .small {
    margin-left: 10px; background: none; color: var(--dim); border: 1px solid var(--edge);
    border-radius: 3px; padding: 1px 8px; font: 12px system-ui, sans-serif; cursor: pointer;
  }
  .small:hover { color: var(--ink); }
  .tabs { display: flex; align-items: center; gap: 18px; margin: 14px 0 8px; }
  .tabs::after { content: ''; flex: 1; border-top: 1px solid var(--edge); }
  .tab {
    background: none; border: 0; border-bottom: 2px solid transparent; padding: 2px 0;
    font: 600 14px var(--serif); letter-spacing: .2em; text-transform: uppercase;
    color: var(--dim); cursor: pointer;
  }
  .tab.on { color: var(--silver); border-bottom-color: var(--silver); }
  .panel { flex: 1; min-height: 0; display: flex; flex-direction: column; }
  input[type=search], select {
    background: var(--panel); color: var(--ink); border: 1px solid var(--edge);
    border-radius: 3px; padding: 2px 8px; font: 13px system-ui, sans-serif;
  }
  #search { width: 220px; }
  .controls { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  .leak_row td { background: var(--alert_bg); }
  .sent { flex: 1; min-height: 0; display: grid; grid-template-columns: 270px 1fr; gap: 10px; }
  .sent_list {
    overflow-y: auto; border: 1px solid var(--edge); border-radius: 4px;
    background: var(--panel);
  }
  .sent_item {
    display: block; width: 100%; text-align: left; background: none; color: var(--ink);
    border: 0; border-bottom: 1px solid var(--soft); padding: 6px 10px; cursor: pointer;
    font: 12px ui-monospace, monospace;
  }
  .sent_item span { display: block; color: var(--dim); font: 12px system-ui, sans-serif; }
  .sent_item.on { background: var(--head); }
  .viewer_pane { display: flex; flex-direction: column; min-height: 0; }
  #viewer {
    flex: 1; min-height: 0; overflow: auto; margin: 0; padding: 8px 10px;
    border: 1px solid var(--edge); border-radius: 4px; background: var(--panel);
    font: 12px/1.45 ui-monospace, monospace; white-space: pre-wrap; overflow-wrap: anywhere;
  }
  @media (max-width: 700px) {
    .sent { grid-template-columns: 1fr; grid-template-rows: 140px 1fr; }
  }

</style>
</head>
<body>
<header>
<svg class="door" viewBox="-2 -2 484 200" role="img" aria-label="The West-gate of Moria">
  <defs>
    <mask id="moon_cut"><rect x="-20" y="-20" width="40" height="40" fill="#fff"/>
      <circle cx="6" cy="-3" r="11" fill="#000"/></mask>
    <g id="tree">
      <path d="M100 196V84"/>
      <path d="M100 156C88 150 76 140 70 124M100 156C112 150 124 140 130 124"/>
      <path d="M100 132C90 126 82 116 80 102M100 132C110 126 118 116 120 102"/>
      <path d="M100 110C94 104 90 96 90 88M100 110C106 104 110 96 110 88"/>
      <circle cx="70" cy="124" r="3"/><circle cx="130" cy="124" r="3"/>
      <circle cx="80" cy="102" r="3"/><circle cx="120" cy="102" r="3"/>
      <circle cx="90" cy="88" r="3"/><circle cx="110" cy="88" r="3"/>
      <circle cx="100" cy="80" r="3"/>
      <g transform="translate(100 50) rotate(-20)">
        <circle r="13" fill="currentColor" stroke="none" mask="url(#moon_cut)"/>
      </g>
    </g>
  </defs>
  <g fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"
    stroke-linejoin="round">
    <path d="M24 196V100A216 94 0 0 1 456 100V196Z"/>
    <use href="#tree"/>
    <use href="#tree" transform="translate(480 0) scale(-1 1)"/>
    <polygon points="240.0,15.0 241.5,26.6 247.3,16.4 244.2,27.8 253.4,20.6 246.2,29.8
      257.6,26.7 247.4,32.5 259.0,34.0 247.4,35.5 257.6,41.3 246.2,38.2
      253.4,47.4 244.2,40.2 247.3,51.6 241.5,41.4 240.0,53.0 238.5,41.4
      232.7,51.6 235.8,40.2 226.6,47.4 233.8,38.2 222.4,41.3 232.6,35.5
      221.0,34.0 232.6,32.5 222.4,26.7 233.8,29.8 226.6,20.6 235.8,27.8
      232.7,16.4 238.5,26.6" fill="currentColor" stroke="none"/>
    <circle cx="214.0" cy="81.0" r="2.4" fill="currentColor" stroke="none"/>
    <circle cx="220.7" cy="73.0" r="2.4" fill="currentColor" stroke="none"/>
    <circle cx="229.7" cy="67.8" r="2.4" fill="currentColor" stroke="none"/>
    <circle cx="240.0" cy="66.0" r="2.4" fill="currentColor" stroke="none"/>
    <circle cx="250.3" cy="67.8" r="2.4" fill="currentColor" stroke="none"/>
    <circle cx="259.3" cy="73.0" r="2.4" fill="currentColor" stroke="none"/>
    <circle cx="266.0" cy="81.0" r="2.4" fill="currentColor" stroke="none"/>
    <path d="M212 114L217 94L229 105L240 90L251 105L263 94L268 114Z"/>
    <path d="M196 124H284L272 136H252V146H274V154H206V146H228V136H208Z"/>
  </g>
</svg>
  <div class="title">
    <h1>Ithildin</h1>
    <p class="motto">Mirrors only starlight and moonlight</p>
    <span id="state">connecting</span>
    <button id="notify" class="small" hidden>Alert me about leaks</button>
  </div>
</header>

<h2>Stats</h2>
<div id="tiles"></div>
<div id="kinds"></div>

<section class="activity">
<nav class="tabs">
  <button id="tab_activity" class="tab on">Activity</button>
  <button id="tab_sent" class="tab">Sent requests</button>
</nav>
<div id="panel_activity" class="panel">
  <div class="bar">
    <div id="filters" class="controls"></div>
    <div class="controls">
      <input id="search" type="search" placeholder="Search the feed" aria-label="Search the feed">
      <select id="session" aria-label="Session"><option value="">All sessions</option></select>
      <p id="feed_count" class="count"></p>
    </div>
  </div>
  <div id="feed_box" class="scroll tall"><div id="feed"></div></div>
</div>
<div id="panel_sent" class="panel" hidden>
  <div class="bar">
    <p id="sent_note" class="count"></p>
    <div class="controls">
      <input id="sent_search" type="search" placeholder="Search this request"
        aria-label="Search this request">
      <p id="sent_count" class="count"></p>
    </div>
  </div>
  <div class="sent">
    <div id="sent_list" class="sent_list"></div>
    <div class="viewer_pane"><pre id="viewer">Pick a request.</pre></div>
  </div>
</div>
</section>
<script>
'use strict';
const POLL_MS = 1000;
const FEED_MAX = 5000;
const MARKS_MAX = 1000;
const ICON = ${JSON.stringify(FAVICON)};
const ICON_ALERT = ${JSON.stringify(FAVICON_ALERT)};
const TYPES = ['leaked', 'masked', 'swapped', 'blocked', 'refused', 'request'];
const shown = new Set(TYPES.filter((type) => type !== 'request'));
const feed = [];
const sessions = new Set();
let since = 0;
let firstPoll = true;
let tab = 'activity';
let chosen = 0;
const texts = new Map();

function byId(id) {
  return document.getElementById(id);
}

function byClass(tagName, className, text) {
  const node = document.createElement(tagName);
  node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function clock(ms) {
  return new Date(ms).toLocaleTimeString();
}

function plural(count, word) {
  return count + ' ' + word + (count === 1 ? '' : 's');
}

// A guard's notice runs long; the full text is in the row's tooltip.
function firstSentence(text) {
  return text.split(/(?<=[.!?])\\s/)[0];
}

function leakDetail(entry) {
  const outcome = entry.action === 'block' ? 'request refused' : 'request sent anyway';
  const what = entry.kind === 'known'
    ? 'A value the proxy always masks was found unmasked'
    : 'Watched string found';
  return what + ' in the outgoing request at ' + entry.where + ' (' + outcome + ')';
}

// What happened, in a sentence, for an entry that has no message of its own.
function sentence(entry) {
  if (entry.type === 'request') {
    const fresh = entry.count ? ', ' + plural(entry.count, 'new value') + ' masked' : '';
    return 'Scanned in ' + entry.ms + ' ms' + fresh;
  }
  if (entry.type === 'refused') return entry.status + ' ' + entry.text;
  if (entry.type === 'blocked') return firstSentence(entry.text);
  return leakDetail(entry);
}

// The message: the request's text around a masked value as it was sent (or the
// stand-in alone), with the stand-in marked. Every piece is a plain text node.
function message(entry) {
  const box = byClass('div', 'msg');
  if (entry.type !== 'masked' && entry.type !== 'swapped') {
    box.classList.add('plain');
    box.textContent = sentence(entry);
    return box;
  }
  const parts = entry.parts || [{ text: entry.standIn, mark: 'this' }];
  for (const part of parts) {
    if (!part.mark) {
      box.append(part.text);
      continue;
    }
    const mark = byClass('mark', '', part.text);
    mark.dataset.type = entry.type;
    mark.dataset.part = part.mark;
    box.appendChild(mark);
  }
  return box;
}

// Under the message, dimmer: what kind of event, of what, and where it came from.
function details(entry) {
  const line = byClass('div', 'meta');
  line.appendChild(byClass('span', 'tag ' + entry.type, entry.type));
  if (entry.kind && entry.type !== 'leaked') line.appendChild(byClass('span', '', entry.kind));
  if (entry.preview) line.appendChild(byClass('span', '', 'value ' + entry.preview));
  if (entry.type === 'swapped') line.appendChild(byClass('span', '', 'back in ' + entry.where));
  if (entry.route)
    line.appendChild(byClass('span', '', entry.route + (entry.endpoint || '')));
  const who = entry.sessionName || entry.session;
  if (who) {
    const span = byClass('span', '', who);
    if (entry.session) span.title = entry.session;
    line.appendChild(span);
  }
  line.appendChild(byClass('span', 'when', clock(entry.time)));
  return line;
}

function feedEntry(entry) {
  const item = byClass('article', entry.type === 'leaked' ? 'entry leak_row' : 'entry');
  if (entry.text) item.title = entry.text;
  item.append(message(entry), details(entry));
  return item;
}

function matches(entry) {
  if (!shown.has(entry.type)) return false;
  const session = byId('session').value;
  if (session && entry.session !== session) return false;
  const needle = byId('search').value.trim().toLowerCase();
  if (!needle) return true;
  const fields = [entry.type, entry.kind, entry.route, entry.endpoint, entry.standIn,
    entry.preview, entry.where, entry.text, entry.session, entry.sessionName];
  return fields.join(' ').toLowerCase().includes(needle);
}

function emptyNote() {
  return byClass('p', 'empty', 'Nothing to show. Send a prompt with a host, an email or a key.');
}

function renderCount() {
  const visible = feed.filter(matches).length;
  byId('feed_count').textContent = visible + ' shown of ' + feed.length + ' kept (newest first)';
}

// Everything again, for a change of filter or a restarted proxy.
function renderFeed() {
  const list = byId('feed');
  list.replaceChildren();
  const entries = feed.filter(matches);
  if (entries.length === 0) list.appendChild(emptyNote());
  for (const entry of entries) list.appendChild(feedEntry(entry));
  renderCount();
}

// Only what is new, on top. Someone reading further down keeps their place.
function addToFeed(entries) {
  const list = byId('feed');
  const box = byId('feed_box');
  const fresh = entries.filter(matches).reverse();
  if (fresh.length > 0) {
    const before = box.scrollHeight;
    const top = box.scrollTop;
    if (list.querySelector('.empty')) list.replaceChildren();
    const fragment = document.createDocumentFragment();
    for (const entry of fresh) fragment.appendChild(feedEntry(entry));
    list.prepend(fragment);
    while (list.children.length > FEED_MAX) list.lastChild.remove();
    if (top > 0) box.scrollTop = top + (box.scrollHeight - before);
  }
  renderCount();
}

function renderFilters() {
  const box = byId('filters');
  for (const type of TYPES) {
    const label = document.createElement('label');
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.checked = shown.has(type);
    input.addEventListener('change', function () {
      if (input.checked) shown.add(type);
      else shown.delete(type);
      renderFeed();
    });
    label.append(input, ' ' + type);
    box.appendChild(label);
  }
  byId('search').addEventListener('input', renderFeed);
  byId('session').addEventListener('change', renderFeed);
}

// Each session seen becomes a choice, by name with its id beside it, so one
// agent's traffic can be picked out.
function noteSessions(entries) {
  const menu = byId('session');
  for (const entry of entries) {
    if (!entry.session || sessions.has(entry.session)) continue;
    sessions.add(entry.session);
    const option = document.createElement('option');
    option.value = entry.session;
    option.textContent = entry.sessionName ? entry.sessionName + ' (' + entry.session + ')' : entry.session;
    menu.appendChild(option);
  }
}

function tile(label, value, note, alarm) {
  const box = document.createElement('div');
  box.className = alarm ? 'tile alarm' : 'tile';
  const big = document.createElement('b');
  big.textContent = value;
  const small = document.createElement('span');
  small.textContent = label + (note ? ' · ' + note : '');
  box.append(big, small);
  return box;
}

function duration(ms) {
  const minutes = Math.floor(ms / 60000);
  if (minutes < 60) return minutes + ' min';
  return Math.floor(minutes / 60) + ' h ' + (minutes % 60) + ' min';
}

// The leak tile. A zero means nothing unless something is watched, so it says
// what is.
function watchTile(stats, watch) {
  const parts = [];
  if (watch.known) parts.push(watch.known + ' known');
  if (watch.terms) parts.push(watch.terms + ' listed, ' + watch.action);
  const note = parts.length ? 'watching ' + parts.join(' + ') : 'nothing watched';
  return tile('leaks found', stats.leaked, note, stats.leaked > 0);
}

function renderStats(stats, watch) {
  const average = stats.requests ? Math.round(stats.scanMsTotal / stats.requests) : 0;
  const routes = Object.entries(stats.routes).map((pair) => pair.join(' ')).join(', ');
  byId('tiles').replaceChildren(
    tile('requests scanned', stats.requests, routes),
    tile('values masked', stats.distinct, plural(stats.replacements, 'replacement')),
    tile('swapped back in reply text', stats.swappedText),
    tile('swapped back in tool calls', stats.swappedCalls),
    tile('tool calls blocked', stats.blocked),
    tile('requests refused', stats.refused),
    watchTile(stats, watch),
    tile('scan time', average + ' ms', 'max ' + stats.scanMsMax + ' ms'),
    tile('uptime', duration(Date.now() - stats.startedAt)),
  );
  const kinds = byId('kinds');
  kinds.replaceChildren('Masked by kind:');
  for (const [kind, count] of Object.entries(stats.kinds).sort((a, b) => b[1] - a[1])) {
    const chip = document.createElement('span');
    chip.className = 'chip';
    chip.append(kind);
    const number = document.createElement('b');
    number.textContent = count;
    chip.appendChild(number);
    kinds.appendChild(chip);
  }
}

function setState(text, className) {
  const state = byId('state');
  state.textContent = text;
  state.className = className;
}

// A leak shows in the tab: the count in the title and a red mark on the icon.
function alertTab(leaked) {
  document.title = (leaked > 0 ? '(' + leaked + ') ' : '') + 'Ithildin';
  byId('icon').href = leaked > 0 ? ICON_ALERT : ICON;
}

function offerNotifications() {
  const button = byId('notify');
  if (!('Notification' in window) || Notification.permission !== 'default') return;
  button.hidden = false;
  button.addEventListener('click', async function () {
    await Notification.requestPermission();
    button.hidden = true;
  });
}

// The places only, never the string: a notice can be seen over someone's shoulder.
function notifyLeaks(entries) {
  const leaks = entries.filter((entry) => entry.type === 'leaked');
  if (leaks.length === 0 || !('Notification' in window)) return;
  if (Notification.permission !== 'granted') return;
  const places = leaks.slice(0, 3).map((entry) => entry.where).join(', ');
  new Notification('Ithildin: ' + plural(leaks.length, 'leak') + ' found', { body: places });
}

async function poll() {
  try {
    const response = await fetch('${ACTIVITY_PATH}?since=' + since, { cache: 'no-store' });
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const data = await response.json();
    setState('proxy up', 'up');
    const restarted = data.next < since;
    if (restarted) feed.length = 0;
    since = data.next;
    feed.unshift(...data.entries.slice().reverse());
    feed.length = Math.min(feed.length, FEED_MAX);
    noteSessions(data.entries);
    renderStats(data.stats, data.watch);
    alertTab(data.stats.leaked);
    if (restarted || firstPoll) renderFeed();
    else addToFeed(data.entries);
    if (!firstPoll) notifyLeaks(data.entries);
    firstPoll = false;
    if (tab === 'sent') await refreshSent();
  } catch (error) {
    setState('proxy not answering', 'down');
  }
}

// The text with each match of the needle in a mark, as plain text nodes.
function highlight(text, needle) {
  const viewer = byId('viewer');
  viewer.replaceChildren();
  if (!needle) {
    viewer.textContent = text;
    return 0;
  }
  const lower = text.toLowerCase();
  const wanted = needle.toLowerCase();
  let count = 0;
  let from = 0;
  for (let at = lower.indexOf(wanted); at >= 0; at = lower.indexOf(wanted, from)) {
    count++;
    if (count <= MARKS_MAX) {
      viewer.append(text.slice(from, at));
      const mark = document.createElement('mark');
      mark.textContent = text.slice(at, at + wanted.length);
      viewer.appendChild(mark);
      from = at + wanted.length;
    } else {
      from = at + wanted.length;
    }
  }
  const marked = Math.min(count, MARKS_MAX);
  if (marked === count) viewer.append(text.slice(from));
  return count;
}

function showSentText() {
  const text = texts.get(chosen);
  if (text === undefined) return;
  const found = highlight(text, byId('sent_search').value.trim());
  const needle = byId('sent_search').value.trim();
  byId('sent_count').textContent = needle ? plural(found, 'match') : '';
  const first = byId('viewer').querySelector('mark');
  if (first) first.scrollIntoView({ block: 'center' });
}

async function chooseSent(id) {
  chosen = id;
  for (const item of byId('sent_list').children)
    item.classList.toggle('on', item.dataset.id === String(id));
  if (!texts.has(id)) {
    const response = await fetch('${REQUEST_PATH}?id=' + id, { cache: 'no-store' });
    texts.set(id, response.ok ? await response.text() : 'This request is no longer kept.');
  }
  showSentText();
}

function sentItem(request) {
  const item = document.createElement('button');
  item.className = 'sent_item' + (request.id === chosen ? ' on' : '');
  item.dataset.id = String(request.id);
  item.textContent = request.route + request.endpoint;
  const small = document.createElement('span');
  const cut = request.cut ? ' (cut)' : '';
  const who = request.sessionName ? request.sessionName + ' · ' : '';
  small.textContent = who + clock(request.time) + ' · ' + request.size + ' characters' + cut;
  item.appendChild(small);
  item.addEventListener('click', () => chooseSent(request.id));
  return item;
}

async function refreshSent() {
  const response = await fetch('${REQUESTS_PATH}', { cache: 'no-store' });
  const data = await response.json();
  const list = byId('sent_list');
  list.replaceChildren(...data.requests.map(sentItem));
  const text = data.enabled
    ? 'The last ' + data.keep + ' requests, as sent upstream after masking (newest first)'
    : 'Off. Set ITHILDIN_KEEP_REQUESTS to a number above 0 to keep requests.';
  byId('sent_note').textContent = text;
  if (data.requests.length > 0 && !data.requests.some((request) => request.id === chosen))
    await chooseSent(data.requests[0].id);
}

function showTab(name) {
  tab = name;
  byId('panel_activity').hidden = name !== 'activity';
  byId('panel_sent').hidden = name !== 'sent';
  byId('tab_activity').classList.toggle('on', name === 'activity');
  byId('tab_sent').classList.toggle('on', name === 'sent');
  if (name === 'sent') refreshSent();
}

byId('tab_activity').addEventListener('click', () => showTab('activity'));
byId('tab_sent').addEventListener('click', () => showTab('sent'));
byId('sent_search').addEventListener('input', showSentText);
renderFilters();
offerNotifications();
poll();
setInterval(poll, POLL_MS);
</script>
</body>
</html>
`;

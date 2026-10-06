// The local dashboard: one page, polling /dashboard/activity (events.ts). A
// bar on top says whether anything leaked; below it, sessions and filters on
// the left, one card per request in the middle, and the request as sent on
// the right.
// It is a string in a module because the package copies only src/*.ts.
//
// Every value on the page reaches the DOM through textContent. Stand-ins, tool
// names and guard notices come from content the proxy does not control, so
// none of it is ever parsed as HTML.

import { IMAGE_NOTICE, INVENTORY_NOTICE, WITHHELD_NOTICE } from "./redact.ts";

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
    --bg: #1d2432; --panel: #252e40; --head: #2d3850; --edge: #3c485e; --soft: #ffffff14;
    --ink: #e9eef6; --dim: #aab5c7; --silver: #d3dcea;
    --masked: #8fb8ff; --masked_bg: #8fb8ff26;
    --swapped: #7fd9b9; --swapped_bg: #7fd9b926;
    --alert: #ff9d8c; --alert_bg: #ff9d8c26;
    --quiet: #c5cedc; --quiet_bg: #ffffff1a;
    --find: #f2d36b; --find_bg: #f2d36b40;
    --stone: #222b3c; --glow: 0 0 6px #d3dcea55;
    --serif: Palatino, 'Palatino Linotype', 'Book Antiqua', Georgia, serif;
    --mono: ui-monospace, monospace;
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
      --find: #8a6400; --find_bg: #f2c94c66;
      --stone: #efede8; --glow: none;
    }
  }
  * { box-sizing: border-box; }
  body {
    font: 14px/1.45 system-ui, sans-serif; color: var(--ink); background: var(--bg);
    margin: 0; height: 100vh; display: flex; flex-direction: column;
    background-image: radial-gradient(ellipse at 50% -30%, var(--head), transparent 65%);
  }
  /* Night over Hollin: a few faint stars behind it all. */
  body::before {
    content: ''; position: fixed; inset: 0; z-index: -1; pointer-events: none; opacity: .5;
    background-image:
      radial-gradient(1px 1px at 12% 18%, var(--silver), transparent),
      radial-gradient(1px 1px at 37% 64%, var(--silver), transparent),
      radial-gradient(1px 1px at 58% 12%, var(--silver), transparent),
      radial-gradient(1.5px 1.5px at 81% 41%, var(--silver), transparent),
      radial-gradient(1px 1px at 92% 83%, var(--silver), transparent),
      radial-gradient(1px 1px at 23% 88%, var(--silver), transparent),
      radial-gradient(1.5px 1.5px at 68% 76%, var(--silver), transparent);
    background-size: 420px 380px;
  }
  @media (prefers-color-scheme: light) { body::before { display: none; } }
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-thumb { background: var(--edge); border-radius: 4px; }
  button { font: inherit; color: inherit; }
  [hidden] { display: none !important; }

  /* The bar: is the proxy up, and did anything leak. The door's lines shine
     as ithildin does, and go red when a leak is found. */
  #bar {
    display: flex; align-items: center; gap: 22px; padding: 8px 20px;
    border-bottom: 1px solid var(--edge); box-shadow: 0 1px 0 var(--soft);
  }
  .door {
    display: block; height: 62px; width: auto; flex: none; color: var(--silver);
    filter: drop-shadow(var(--glow));
  }
  .brand { flex: none; }
  h1 {
    margin: 0; font: 600 21px/1.1 var(--serif); letter-spacing: .4em;
    text-transform: uppercase; color: var(--silver); text-shadow: var(--glow);
  }
  .motto { margin: 2px 0 4px; font: italic 13px var(--serif); color: var(--dim); }
  #state { display: flex; align-items: center; gap: 6px; color: var(--dim); font-size: 11px; }
  #state::before {
    content: ''; width: 9px; height: 9px; border-radius: 50%; background: var(--dim);
  }
  #state.up::before { background: var(--swapped); }
  #state.down { color: var(--alert); }
  #state.down::before { background: var(--alert); }
  #verdict {
    flex: 1; min-width: 0; padding-left: 22px; border-left: 1px solid var(--edge);
  }
  #verdict b { display: block; font: 600 21px/1.2 var(--serif); letter-spacing: .02em; }
  #verdict span { color: var(--dim); font-size: 12px; }
  #verdict.ok b { color: var(--silver); text-shadow: var(--glow); }
  #verdict.unwatched b { color: var(--dim); }
  #verdict.bad b { color: var(--alert); }
  .small {
    background: none; color: var(--dim); border: 1px solid var(--edge);
    border-radius: 3px; padding: 2px 8px; font-size: 12px; cursor: pointer;
  }
  .small:hover { color: var(--ink); }

  main {
    flex: 1; min-height: 0; display: grid; gap: 0;
    grid-template-columns: 250px minmax(0, 1fr);
  }
  main > * { min-height: 0; overflow-y: auto; }
  h2 {
    display: flex; align-items: center; gap: 8px; margin: 18px 0 6px;
    font: 600 12px var(--serif); letter-spacing: .22em; text-transform: uppercase;
    color: var(--silver);
  }
  h2::before { content: '\\2726'; font-size: 10px; color: var(--dim); }
  h2::after { content: ''; flex: 1; border-top: 1px solid var(--edge); }
  /* Every section of the left column folds the same way, and remembers it. */
  .section summary h2 { cursor: pointer; }
  .section summary:hover h2 { color: var(--ink); }
  .chev { order: 1; font-size: 10px; color: var(--dim); }
  .chev::before { content: '\\25be'; }
  .section:not([open]) .chev::before { content: '\\25b8'; }
  .section:not([open]) h2 { color: var(--dim); }

  /* Left: sessions, what to show, and the totals. */
  #side { padding: 0 14px 14px; border-right: 1px solid var(--edge); }
  #side dl, .pick, .kind { font-family: var(--serif); }
  .pick {
    display: flex; align-items: baseline; gap: 6px; width: 100%; text-align: left;
    background: none; border: 0; border-radius: 4px; padding: 4px 8px; cursor: pointer;
  }
  .pick:hover { background: var(--soft); }
  .pick.on { background: var(--head); color: var(--silver); box-shadow: inset 2px 0 var(--silver); }
  .pick small { color: var(--dim); font: 11px var(--mono); }
  .kind { display: grid; grid-template-columns: 1fr auto; gap: 0 8px; font-size: 12px; }
  .kind i {
    grid-column: 1 / -1; height: 3px; margin: 2px 0 6px; border-radius: 2px;
    background: var(--masked); opacity: .7;
  }
  #fold_numbers dl { margin-top: 10px; }
  dl { display: grid; grid-template-columns: 1fr auto; gap: 3px 8px; margin: 0; font-size: 12px; }
  dt { color: var(--dim); }
  dd { margin: 0; text-align: right; }

  /* Middle: one card per request. */
  /* Main: the picked session, and its conversation as the provider saw it. */
  #center { display: flex; flex-direction: column; overflow: hidden; }
  #session_head { padding: 14px 18px 0; }
  #session_title {
    margin: 0; font: 600 20px/1.2 var(--serif); color: var(--silver); text-shadow: var(--glow);
  }
  #session_note { margin: 4px 0 0; color: var(--dim); font-size: 12px; }
  #session_note .leaks { color: var(--alert); font-weight: 600; }
  #alerts { margin-top: 8px; }
  .alert {
    display: flex; gap: 8px; align-items: baseline; font-size: 12px; color: var(--alert);
    padding: 3px 8px; border-left: 2px solid var(--alert); background: var(--alert_bg);
    margin-bottom: 3px; border-radius: 0 3px 3px 0;
  }
  .alert .when, .other_line .when { color: var(--dim); font: 11px var(--mono); flex: none; }
  .alert b { flex: none; }
  .other_line { display: flex; gap: 10px; margin-bottom: 4px; }
  .find { display: flex; gap: 10px; align-items: center; padding: 10px 18px; flex-wrap: wrap; }
  input[type=search] {
    flex: 1; min-width: 160px; background: var(--panel); color: var(--ink);
    border: 1px solid var(--edge); border-radius: 4px; padding: 4px 10px;
    font: 13px system-ui, sans-serif;
  }
  .count { color: var(--dim); font-size: 12px; white-space: nowrap; }
  .pick.session { align-items: center; }
  .pick .label { display: flex; flex-direction: column; min-width: 0; flex: 1; }
  .pick .title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  mark {
    background: var(--masked_bg); color: var(--ink); outline: 1px solid var(--masked);
    border-radius: 2px; padding: 0 1px;
  }
  /* One look per meaning, everywhere: masked values blue, what was held back
     red, search hits gold. The mark a click went to pulses once. */
  mark[data-type=held], .key.held mark {
    background: var(--alert_bg); color: var(--alert); outline-color: var(--alert);
  }
  mark[data-type=found] { background: var(--find_bg); outline-color: var(--find); }
  @keyframes pulse {
    from { box-shadow: 0 0 0 5px var(--masked_bg), var(--glow); }
    to { box-shadow: 0 0 0 0 transparent; }
  }
  mark.at { animation: pulse 1.4s ease-out; }
  /* A stand-in the model used, that came back to it as the real value. */
  mark[data-back]::after { content: ' \\21a9'; color: var(--swapped); font-weight: 600; }
  .key.back mark { background: var(--masked_bg); }
  .key.back mark::after { content: ' \\21a9'; color: var(--swapped); }
  #legend { display: flex; flex-wrap: wrap; gap: 4px 14px; }
  .key {
    background: none; border: 0; padding: 0; cursor: pointer; color: var(--dim);
    font-size: 12px;
  }
  .key:hover { color: var(--ink); }
  .key mark { padding: 0 5px; font: 600 11px var(--mono); }
  .badge {
    margin-left: 8px; padding: 0 6px; border-radius: 8px; font: 600 10px/16px var(--mono);
    background: var(--masked_bg); color: var(--masked);
  }
  .badge.held { background: var(--alert_bg); color: var(--alert); }
  .badge.back { background: var(--swapped_bg); color: var(--swapped); }
  .flag {
    margin: 0 0 6px; padding: 3px 8px; font-size: 12px; font-weight: 600; color: var(--alert);
    background: var(--alert_bg); border-left: 2px solid var(--alert); border-radius: 0 3px 3px 0;
  }
  .empty { color: var(--dim); font: italic 15px var(--serif); padding: 24px 0; text-align: center; }
  .empty b { display: block; color: var(--silver); font-size: 18px; text-shadow: var(--glow); }

  .view.on { color: var(--silver); border-color: var(--silver); }
  .view:disabled { opacity: .4; cursor: default; }
  #viewer {
    flex: 1; min-height: 0; overflow: auto; margin: 0 18px 14px; padding: 10px 12px;
    border: 1px solid var(--edge); border-radius: 4px; background: var(--panel);
  }
  #viewer.raw {
    font: 12px/1.45 var(--mono); white-space: pre-wrap; overflow-wrap: anywhere;
  }
  /* The conversation, set like an agent's terminal. */
  #viewer:not(.raw) { font: 12.5px/1.5 var(--mono); }
  .step { display: flex; gap: 8px; margin: 0 0 8px; }
  details.step, .step.call { display: block; }
  .glyph { flex: none; width: 1em; color: var(--dim); }
  .said, .body { white-space: pre-wrap; overflow-wrap: anywhere; min-width: 0; }
  .step.prompt { padding: 6px 8px; border-radius: 4px; background: var(--head); }
  /* The timeline: each turn on a rail, a star where it starts. */
  .turn {
    margin-left: 6px; padding: 0 0 6px 16px; border-left: 1px solid var(--edge);
  }
  .turn.latest { border-left-color: var(--silver); }
  .turn_head {
    display: flex; align-items: center; gap: 8px; margin: 0 0 8px -22px; padding-top: 14px;
    font: 600 11px var(--serif); letter-spacing: .2em; text-transform: uppercase;
    color: var(--dim);
  }
  .turn:first-child .turn_head { padding-top: 0; }
  .turn_head::before {
    content: '\\2726'; width: 11px; text-align: center; background: var(--panel);
    color: var(--dim); font-size: 11px;
  }
  .turn_head::after { content: ''; flex: 1; border-top: 1px solid var(--soft); }
  .turn.latest .turn_head, .turn.latest .turn_head::before {
    color: var(--silver); text-shadow: var(--glow);
  }
  .step.prompt .glyph { color: var(--silver); }
  .step.reply .glyph { color: var(--ink); }
  .step.call .glyph { color: var(--swapped); }
  .head { display: flex; gap: 8px; }
  .head b { font-weight: 600; }
  .args { color: var(--dim); overflow-wrap: anywhere; min-width: 0; }
  .step.media .said { color: var(--dim); font-style: italic; }
  summary { cursor: pointer; list-style: none; }
  summary::-webkit-details-marker { display: none; }
  .gist { color: var(--dim); }
  summary:hover .gist { color: var(--ink); }
  details.out { margin: 2px 0 0 1.6em; }
  .body {
    max-height: 320px; overflow: auto; margin: 4px 0 0; padding: 4px 10px;
    border-left: 1px solid var(--edge);
  }

  @media (max-width: 700px) {
    .door, .motto { display: none; }
    main { display: flex; flex-direction: column; overflow-y: auto; }
    #side { border-right: 0; }
    #center { min-height: 80vh; }
  }
</style>
</head>
<body>
<header id="bar">
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
  <div class="brand">
    <h1>Ithildin</h1>
    <p class="motto">Mirrors only starlight and moonlight</p>
    <span id="state">connecting</span>
  </div>
  <div id="verdict"><b>Connecting</b><span></span></div>
  <button id="notify" class="small" hidden>Alert me about leaks</button>
</header>
<main>
<aside id="side">
  <details class="section" id="fold_sessions" open>
    <summary><h2>Sessions<span class="chev"></span></h2></summary>
    <div id="sessions"></div>
  </details>
  <details class="section" id="fold_numbers">
    <summary><h2>Numbers<span class="chev"></span></h2></summary>
    <div id="kinds"></div>
    <dl id="totals"></dl>
  </details>
</aside>
<section id="center">
  <div id="session_head">
    <h3 id="session_title">Connecting</h3>
    <p id="session_note"></p>
    <div id="alerts"></div>
  </div>
  <div class="find">
    <input id="detail_search" type="search" placeholder="Search this conversation"
      aria-label="Search this conversation">
    <span id="detail_count" class="count"></span>
    <div id="legend"></div>
    <span id="view_note" class="count"
      title="The conversation as it left this machine, after masking"></span>
    <button id="view_chat" class="small view on" data-view="chat">Conversation</button>
    <button id="view_raw" class="small view" data-view="raw">Raw</button>
  </div>
  <div id="viewer"></div>
</section>
</main>
<script>
'use strict';
const POLL_MS = 1000;
const FEED_MAX = 5000;
const MARKS_MAX = 1000;
const ICON = ${JSON.stringify(FAVICON)};
const ICON_ALERT = ${JSON.stringify(FAVICON_ALERT)};
// What the proxy puts in place of what it holds back, to mark in a request.
const HELD_NOTICES = ${JSON.stringify(
  [IMAGE_NOTICE, INVENTORY_NOTICE, WITHHELD_NOTICE].map((notice) => notice.split(". ")[0]!),
)};
// Stand-ins seen, marked in a conversation: enough for a long session.
const KNOWN_MAX = 300;
// Requests without a session, and refusals, gather under this one.
const OTHER = '';
const feed = [];
// Each session the page has seen, in the order seen: its names, when it last
// sent, and what happened in it.
const sessions = new Map();
let chosen;
let since = 0;
let firstPoll = true;
let lastStats;
let lastWatch;
const texts = new Map();
let shownId = 0;
let view = 'chat';

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

// A guard's notice runs long; the full text is in the card's tooltip.
function firstSentence(text) {
  return text.split(/(?<=[.!?])\\s/)[0];
}

function leakDetail(entry) {
  const outcome = entry.action === 'block' ? 'request refused' : 'request sent anyway';
  const what = entry.kind === 'known'
    ? 'A value the proxy always masks was found unmasked'
    : 'Watched string found';
  return what + ' at ' + entry.where + ' (' + outcome + ')';
}

// What happened, per session, from the events as they come.
function noteEntries(entries) {
  for (const entry of entries) {
    const id = entry.session || OTHER;
    let known = sessions.get(id);
    if (!known) {
      const name = entry.sessionName || (id === OTHER ? 'Other traffic' : id);
      known = { id, name, last: 0, masked: 0, swapped: 0, held: 0, leaked: 0 };
      sessions.set(id, known);
    }
    known.last = Math.max(known.last, entry.time);
    if (entry.type === 'masked') known.masked++;
    else if (entry.type === 'swapped') known.swapped++;
    else if (entry.type === 'blocked' || entry.type === 'refused') known.held++;
    else if (entry.type === 'leaked') known.leaked++;
  }
}

// The names the proxy has for each session: its agent's number, and the
// title the agent gave it, if any (titles.ts).
function noteNames(list) {
  for (const named of list || []) {
    const known = sessions.get(named.id);
    if (!known) continue;
    known.name = named.name;
    known.title = named.title;
  }
}

function sessionLabel(known) {
  return known.title || known.name;
}

// The sessions, in the order seen so the list holds still; other traffic last.
function renderSessions() {
  const list = [...sessions.values()].sort((a, b) => (a.id === OTHER) - (b.id === OTHER));
  const rows = list.map((known) => {
    const button = byClass('button', 'pick session' + (known.id === chosen ? ' on' : ''));
    const label = byClass('span', 'label');
    label.append(byClass('span', 'title', sessionLabel(known)),
      byClass('small', '', (known.title ? known.name + ' \\u00b7 ' : '') + clock(known.last)));
    button.appendChild(label);
    if (known.leaked > 0) {
      const leaks = byClass('span', 'badge held', String(known.leaked));
      leaks.title = plural(known.leaked, 'leak');
      button.appendChild(leaks);
    }
    button.title = known.id === OTHER ? 'Requests without a session, and refusals'
      : 'Session ' + known.id;
    button.addEventListener('click', () => {
      chosen = known.id;
      shownId = 0;
      renderSessions();
      showSession();
    });
    return button;
  });
  byId('sessions').replaceChildren(...rows);
  if (rows.length === 0) byId('sessions').appendChild(byClass('p', 'count', 'None yet'));
}

// The picked session's name, what happened in it, and what went wrong.
function renderHead(known) {
  if (!known) {
    byId('session_title').textContent = 'No sessions yet';
    byId('session_note').textContent = '';
    byId('alerts').replaceChildren();
    return;
  }
  byId('session_title').textContent = sessionLabel(known);
  const said = [];
  if (known.id !== OTHER) said.push(known.title ? known.name : '', known.id);
  said.push('last request ' + clock(known.last));
  const counts = [
    plural(known.masked, 'value') + ' masked',
    known.swapped + ' swapped back',
    known.held ? known.held + ' held back' : '',
  ];
  const note = byId('session_note');
  note.replaceChildren(said.filter(Boolean).join(' \\u00b7 '), byClass('br', ''),
    counts.filter(Boolean).join(' \\u00b7 '));
  if (known.leaked > 0)
    note.append(' \\u00b7 ', byClass('span', 'leaks', plural(known.leaked, 'leak')));
  const alarms = feed.filter((entry) => (entry.session || OTHER) === known.id &&
    (entry.type === 'leaked' || entry.type === 'blocked' || entry.type === 'refused'));
  const lines = alarms.slice(0, ALERTS_SHOWN).map((entry) => {
    const line = byClass('div', 'alert');
    const what = entry.type === 'leaked' ? 'Leak' : entry.type === 'blocked' ? 'Blocked'
      : 'Refused ' + entry.status;
    const text = entry.type === 'leaked' ? leakDetail(entry) : entry.type === 'blocked'
      ? firstSentence(entry.text) : entry.text;
    line.append(byClass('span', 'when', clock(entry.time)), byClass('b', '', what), text);
    if (entry.text) line.title = entry.text;
    return line;
  });
  if (alarms.length > ALERTS_SHOWN)
    lines.push(byClass('div', 'count', 'and ' + (alarms.length - ALERTS_SHOWN) + ' earlier'));
  byId('alerts').replaceChildren(...lines);
}
const ALERTS_SHOWN = 4;

// Traffic without a session has no conversation to show: a line per event.
function renderOther() {
  const viewer = byId('viewer');
  viewer.classList.add('raw');
  const lines = feed.filter((entry) => !entry.session).slice(0, 200).map((entry) => {
    const line = byClass('div', 'other_line');
    const text = entry.type === 'refused' ? 'Refused ' + entry.status + ': ' + entry.text
      : entry.type === 'request' ? 'Request ' + entry.route + (entry.endpoint || '') +
        ', scanned in ' + entry.ms + ' ms'
        : entry.type + ' ' + (entry.standIn || entry.where || entry.text || '');
    line.append(byClass('span', 'when', clock(entry.time)), text);
    return line;
  });
  viewer.replaceChildren(...lines);
}

function emptyNote() {
  const note = byClass('div', 'empty');
  note.append(byClass('b', '', 'Speak, friend, and enter'),
    'Nothing yet. Send a prompt with a host, an email or a key.');
  return note;
}

// The picked session's conversation: its newest turn the proxy keeps, read
// again only when a newer one arrives.
async function showSession() {
  const known = sessions.get(chosen);
  renderHead(known);
  const viewer = byId('viewer');
  if (!known) {
    viewer.replaceChildren(emptyNote());
    return;
  }
  if (known.id === OTHER) {
    renderOther();
    return;
  }
  const list = await (await fetch('${REQUESTS_PATH}', { cache: 'no-store' })).json();
  if (chosen !== known.id) return;
  if (!list.enabled) {
    viewer.classList.add('raw');
    viewer.textContent = 'Off. Set ITHILDIN_KEEP_REQUESTS to a number above 0 to keep requests.';
    return;
  }
  const own = list.requests.filter((request) => request.session === known.id);
  const sent = own.find((request) => request.main) || own[0];
  if (!sent) {
    viewer.classList.add('raw');
    viewer.textContent = 'No request of this session is kept any more.';
    return;
  }
  if (sent.id === shownId) return;
  if (!texts.has(sent.id)) {
    const response = await fetch('${REQUEST_PATH}?id=' + sent.id, { cache: 'no-store' });
    if (!response.ok) return;
    texts.set(sent.id, await response.text());
  }
  if (chosen !== known.id) return;
  const first = shownId === 0;
  shownId = sent.id;
  byId('view_note').textContent = 'As sent ' + clock(sent.time) + (sent.cut ? ', cut' : '');
  showText(first ? 'top' : 'keep');
}

function duration(ms) {
  const minutes = Math.floor(ms / 60000);
  if (minutes < 60) return minutes + ' min';
  return Math.floor(minutes / 60) + ' h ' + (minutes % 60) + ' min';
}

// The answer first: did anything leak, and what is watched for one.
function renderVerdict(stats, watch) {
  const verdict = byId('verdict');
  const watched = watch.known + watch.terms;
  const detail = [];
  if (watch.known) detail.push(plural(watch.known, 'value') + ' the proxy always masks');
  if (watch.terms)
    detail.push(plural(watch.terms, 'listed string') + ' (' + watch.action + ')');
  let title;
  let note;
  let tip = detail.length ? 'Watching ' + detail.join(' and ') + '.' : '';
  if (stats.leaked > 0) {
    const last = feed.find((entry) => entry.type === 'leaked');
    verdict.className = 'bad';
    title = plural(stats.leaked, 'leak') + ' found';
    note = last ? 'Latest ' + clock(last.time) : '';
    if (last) tip = 'Latest in ' + last.where + '. ' + tip;
  } else if (watched > 0) {
    verdict.className = 'ok';
    title = 'No leaks';
    note = 'Watching ' + plural(watched, 'value');
  } else {
    verdict.className = 'unwatched';
    title = 'Nothing watched';
    note = 'Add a watch list to config.json';
  }
  verdict.title = tip;
  verdict.replaceChildren(byClass('b', '', title), byClass('span', '', note));
}

function renderStats(stats, watch) {
  renderVerdict(stats, watch);
  const kinds = Object.entries(stats.kinds).sort((a, b) => b[1] - a[1]);
  const most = kinds.length ? kinds[0][1] : 1;
  byId('kinds').replaceChildren(...kinds.map(([kind, count]) => {
    const row = byClass('div', 'kind');
    const bar = byClass('i', '');
    bar.style.width = Math.max(4, Math.round((count / most) * 100)) + '%';
    row.append(byClass('span', '', kind), byClass('span', '', String(count)), bar);
    return row;
  }));
  if (kinds.length === 0) byId('kinds').appendChild(byClass('p', 'count', 'None yet'));
  const average = stats.requests ? Math.round(stats.scanMsTotal / stats.requests) : 0;
  const routes = Object.entries(stats.routes).map((pair) => pair.join(' ')).join(', ');
  const rows = [
    ['Requests scanned', stats.requests],
    ['Routes', routes || 'none'],
    ['Replacements', stats.replacements],
    ['Swapped in replies', stats.swappedText],
    ['Swapped in tool calls', stats.swappedCalls],
    ['Tool calls blocked', stats.blocked],
    ['Requests refused', stats.refused],
    ['Scan time', average + ' ms, max ' + stats.scanMsMax],
    ['Uptime', duration(Date.now() - stats.startedAt)],
  ];
  byId('totals').replaceChildren(...rows.flatMap(([label, value]) =>
    [byClass('dt', '', label), byClass('dd', '', String(value))]));
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
    if (data.next < since) {
      feed.length = 0;
      sessions.clear();
      texts.clear();
      shownId = 0;
    }
    since = data.next;
    feed.unshift(...data.entries.slice().reverse());
    feed.length = Math.min(feed.length, FEED_MAX);
    noteEntries(data.entries);
    noteNames(data.sessions);
    lastStats = data.stats;
    lastWatch = data.watch;
    renderStats(data.stats, data.watch);
    alertTab(data.stats.leaked);
    // At first, the session that sent last; after that, the one picked.
    if (chosen === undefined || !sessions.has(chosen)) {
      const latest = [...sessions.values()].filter((known) => known.id !== OTHER)
        .sort((a, b) => b.last - a.last)[0];
      chosen = latest ? latest.id : sessions.has(OTHER) ? OTHER : undefined;
    }
    renderSessions();
    if (firstPoll || data.entries.some((entry) => (entry.session || OTHER) === chosen))
      await showSession();
    if (!firstPoll) notifyLeaks(data.entries);
    firstPoll = false;
  } catch (error) {
    setState('proxy not answering', 'down');
  }
}

// The request's conversation in order, as plain items to lay out: who said
// it, what kind of thing it is, and its text. Anthropic Messages, Chat
// Completions and Responses, the formats the proxy forwards.
function turns(body) {
  const out = [];
  // Which message of the list an item came from, so the page can tell turns.
  let at = -1;
  const add = (who, kind, text, name, id) => {
    if (text !== '') out.push({ who, kind, text, name, at, ...(id ? { id } : {}) });
  };
  const asText = (value) => (typeof value === 'string' ? value : JSON.stringify(value, null, 1));
  const roleOf = (role) => (role === 'developer' ? 'system' : role === 'tool' ? 'tool' : role);
  const partText = (part) =>
    typeof part === 'string' ? part
      : part && typeof part.text === 'string' ? part.text
        : '[' + (part && part.type) + ']';
  const blocks = (who, content) => {
    if (typeof content === 'string') return add(who, who, content);
    if (!Array.isArray(content))
      return content == null ? undefined : add(who, 'other', asText(content));
    for (const block of content) {
      if (typeof block === 'string') {
        add(who, who, block);
        continue;
      }
      if (!block || typeof block !== 'object') continue;
      switch (block.type) {
        case 'text': case 'input_text': case 'output_text':
          add(who, who, String(block.text ?? ''));
          break;
        case 'thinking':
          add(who, 'thinking', String(block.thinking ?? ''));
          break;
        case 'redacted_thinking':
          add(who, 'thinking', '(hidden by the provider)');
          break;
        case 'tool_use': case 'server_tool_use':
          add(who, 'tool_call', asText(block.input ?? {}), block.name, block.id);
          break;
        case 'tool_result': {
          const result = block.content;
          const text = Array.isArray(result)
            ? result.map(partText).join('\\n')
            : asText(result ?? '');
          add(who, 'tool_result', text, undefined, block.tool_use_id);
          break;
        }
        case 'image': case 'document': case 'image_url': case 'input_image':
        case 'file': case 'input_file': case 'input_audio':
          add(who, 'media', '[' + block.type + ']');
          break;
        default:
          add(who, 'other', asText(block));
      }
    }
  };
  if (body.system !== undefined) blocks('system', body.system);
  if (typeof body.instructions === 'string') add('system', 'system', body.instructions);
  const list = Array.isArray(body.messages) ? body.messages
    : typeof body.input === 'string' ? [{ role: 'user', content: body.input }]
      : Array.isArray(body.input) ? body.input : [];
  for (const item of list) {
    at++;
    if (!item || typeof item !== 'object') continue;
    if (item.type === 'function_call' || item.type === 'custom_tool_call')
      add('assistant', 'tool_call', asText(item.arguments ?? item.input ?? ''), item.name,
        item.call_id);
    else if (item.type === 'function_call_output' || item.type === 'custom_tool_call_output')
      add('tool', 'tool_result', asText(item.output ?? ''), undefined, item.call_id);
    else if (item.type === 'reasoning')
      add('assistant', 'thinking', (item.summary || []).map(partText).join('\\n') || '(hidden)');
    else if (item.role === 'tool')
      add('tool', 'tool_result', asText(item.content ?? ''), undefined, item.tool_call_id);
    else if (item.role) {
      blocks(roleOf(item.role), item.content);
      for (const call of item.tool_calls || [])
        add('assistant', 'tool_call', asText(call.function?.arguments ?? ''), call.function?.name,
          call.id);
    }
  }
  if (Array.isArray(body.tools) && body.tools.length > 0) {
    const names = body.tools.map((tool) => tool.name || tool.function?.name || tool.type);
    out.unshift({ who: 'tools', kind: 'tools', text: names.join(', '), name: body.tools.length });
  }
  return out;
}

// The text in a node, with each stand-in of the card and each match of the
// search marked, as plain text nodes. Returns how many search matches.
function markInto(node, text, wants, needle) {
  const lower = text.toLowerCase();
  const found = [];
  const look = (wanted, type, fold, title, back) => {
    if (!wanted) return 0;
    const haystack = fold ? lower : text;
    const what = fold ? wanted.toLowerCase() : wanted;
    let count = 0;
    for (let at = haystack.indexOf(what); at >= 0; at = haystack.indexOf(what, at + what.length)) {
      count++;
      if (found.length < MARKS_MAX) found.push({ at, end: at + what.length, type, title, back });
    }
    return count;
  };
  for (const want of wants) look(want.text, want.type, false, want.title, want.back);
  const matches = look(needle, 'found', true);
  found.sort((a, b) => a.at - b.at || b.end - a.end);
  let from = 0;
  for (const hit of found) {
    if (hit.at < from) continue;
    node.append(text.slice(from, hit.at));
    const mark = document.createElement('mark');
    mark.textContent = text.slice(hit.at, hit.end);
    mark.dataset.type = hit.type;
    if (hit.title) mark.title = hit.title;
    if (hit.back) mark.dataset.back = '';
    node.appendChild(mark);
    from = hit.end;
  }
  node.append(text.slice(from));
  return matches;
}

// Harness text in a user turn (reminders, command output): folded, not shown
// as something the user typed.
const WRAPPED = /^\\s*<([a-z][\\w-]*)[\\s>]/;
// What a tool call is about, in a few words: its command, file or pattern.
const BRIEF_KEYS = ['command', 'cmd', 'file_path', 'path', 'pattern', 'url', 'query',
  'description', 'prompt'];

function oneLine(text, max) {
  const line = text.replace(/\\s+/g, ' ').trim();
  return line.length > max ? line.slice(0, max) + '\\u2026' : line;
}

// The call's gist, and whether its input holds more than that.
function brief(item) {
  let args;
  try {
    args = JSON.parse(item.text);
  } catch {
    args = undefined;
  }
  if (args && typeof args === 'object' && !Array.isArray(args)) {
    const key = BRIEF_KEYS.find((name) => typeof args[name] === 'string');
    if (key) return { text: oneLine(args[key], 100), more: Object.keys(args).length > 1 };
  }
  return { text: oneLine(item.text, 100), more: item.text.length > 100 };
}

// A folded block: one dim line, opened when something in it is marked.
function fold(className, head, text, wants, needle) {
  const box = byClass('details', 'step ' + className);
  const summary = document.createElement('summary');
  summary.appendChild(byClass('span', 'gist', head));
  const body = byClass('div', 'body');
  const matches = markInto(body, text, wants, needle);
  box.append(summary, body);
  // Folded, it still says what it holds; it opens for this card's values,
  // what was held back, and the search.
  for (const [type, selector] of MARK_KINDS) {
    const count = body.querySelectorAll(selector).length;
    if (count > 0) summary.appendChild(byClass('span', 'badge ' + type, String(count)));
  }
  box.open = body.querySelector('mark:not([data-type=masked])') !== null;
  return { node: box, matches };
}

function said(className, glyph, text, wants, needle) {
  const box = byClass('div', 'step ' + className);
  const words = byClass('div', 'said');
  const matches = markInto(words, text, wants, needle);
  box.append(byClass('span', 'glyph', glyph), words);
  return { node: box, matches };
}

// The conversation the way an agent's terminal shows it, newest turn first:
// a prompt after "\\u203a", the model's words and each tool call after
// "\\u23fa", a call's result under it after "\\u23bf", and the system prompt,
// the tools and harness text folded. The model's own words get the marks
// that say which stand-ins came back to it real; a leak is flagged on the
// message it was found in.
function conversation(items, marks, needle, leaks) {
  const results = new Map();
  for (const item of items)
    if (item.kind === 'tool_result' && item.id) results.set(item.id, item);
  const paired = new Set();
  const flagged = new Set();
  // A turn starts at each message holding something the user typed, not a
  // reminder or a tool result beside one. Each turn hangs on a rail.
  const prompts = new Set(items
    .filter((item) => item.kind === 'user' && !WRAPPED.test(item.text))
    .map((item) => item.at));
  const nodes = [];
  let turn;
  let count = 0;
  let started = -2;
  const start = (title) => {
    turn = byClass('div', 'turn');
    turn.appendChild(byClass('div', 'turn_head', title));
    nodes.push(turn);
  };
  let matches = 0;
  const put = (item, shown) => {
    if (!turn) start('Before the first prompt');
    const found = leaks.get(item.at);
    if (found && !flagged.has(item.at)) {
      flagged.add(item.at);
      const flag = byClass('div', 'flag', '\\u26a0 Leak: ' + leakDetail(found[0]));
      turn.appendChild(flag);
    }
    turn.appendChild(shown.node);
    matches += shown.matches;
  };
  const plain = marks.plain;
  const model = marks.model;
  for (const item of items) {
    if (prompts.has(item.at) && item.at !== started) {
      started = item.at;
      start('Turn ' + ++count);
    }
    if (item.kind === 'tools') {
      put(item, fold('meta', item.name + ' tools offered', item.text, plain, needle));
    } else if (item.kind === 'system') {
      const size = item.text.length + ' characters';
      put(item, fold('meta', 'System prompt \\u00b7 ' + size, item.text, plain, needle));
    } else if (item.kind === 'user') {
      const tag = WRAPPED.exec(item.text);
      if (tag) put(item, fold('meta', '\\u2699 ' + tag[1], item.text, plain, needle));
      else put(item, said('prompt', '\\u203a', item.text, plain, needle));
    } else if (item.kind === 'assistant') {
      put(item, said('reply', '\\u23fa', item.text, model, needle));
    } else if (item.kind === 'thinking') {
      put(item, fold('meta', '\\u273b Thinking', item.text, plain, needle));
    } else if (item.kind === 'tool_call') {
      const result = item.id ? results.get(item.id) : undefined;
      if (result) paired.add(result);
      const gist = brief(item);
      const box = byClass('div', 'step call');
      const head = byClass('div', 'head');
      const args = byClass('span', 'args');
      matches += markInto(args, '(' + gist.text + ')', model, needle);
      head.append(byClass('span', 'glyph', '\\u23fa'), byClass('b', '', item.name || 'tool'), args);
      const output = result ? result.text : '';
      const lines = output.split('\\n');
      const first = output ? oneLine(lines[0], 90) : '(no output)';
      const more = lines.length > 1 ? '  \\u2026 +' + (lines.length - 1) + ' lines' : '';
      const body = (gist.more ? item.text + '\\n\\n' : '') + output;
      const shown = fold('out', '\\u23bf  ' + first + more, body, plain, needle);
      matches += shown.matches;
      box.append(head, shown.node);
      put(item, { node: box, matches: 0 });
    } else if (item.kind === 'tool_result') {
      if (paired.has(item)) continue;
      put(item, fold('out', '\\u23bf  ' + oneLine(item.text, 90), item.text, plain, needle));
    } else if (item.kind === 'media') {
      put(item, said('media', '', item.text, plain, needle));
    } else {
      put(item, fold('meta', item.who + ' \\u00b7 ' + item.kind, item.text, plain, needle));
    }
  }
  const last = nodes.at(-1);
  if (count > 0 && last) {
    last.classList.add('latest');
    last.firstChild.textContent += ' \\u00b7 latest';
  }
  return { nodes: nodes.reverse(), matches };
}

// What to mark in a session's conversation: the stand-ins the proxy made,
// and what it held back (a guard's refusal, a withheld file or image). In
// the model's own words, a stand-in it used that came back real is marked so.
function marksFor(id) {
  const back = new Map();
  const known = new Map();
  for (const entry of feed) {
    if (!entry.standIn) continue;
    if (entry.type === 'swapped' && (entry.session || OTHER) === id) {
      if (!back.has(entry.standIn)) back.set(entry.standIn, new Set());
      back.get(entry.standIn).add(entry.where === 'reply text' ? 'the reply' : entry.where);
    }
    if (known.size < KNOWN_MAX && !known.has(entry.standIn)) known.set(entry.standIn, entry);
  }
  const held = new Map(HELD_NOTICES.map((text) => [text, 'The proxy held this back']));
  for (const entry of feed)
    if (entry.type === 'blocked') held.set(firstSentence(entry.text), entry.text);
  const heldMarks = [...held].map(([text, title]) => ({ text, type: 'held', title }));
  const value = ([text, entry]) => ({ text, type: 'masked', title: valueTitle(entry) });
  const plain = [...known].map(value);
  const model = [...known].map(([text, entry]) => !back.has(text) ? value([text, entry]) : {
    text, type: 'masked', back: true,
    title: valueTitle(entry) + '\\nThe model used it: swapped back to the real value in ' +
      [...back.get(text)].join(', '),
  });
  return { plain: plain.concat(heldMarks), model: model.concat(heldMarks) };
}

// Where each leak of a session was found, by the message it is in.
function leaksFor(id) {
  const leaks = new Map();
  for (const entry of feed) {
    if (entry.type !== 'leaked' || (entry.session || OTHER) !== id) continue;
    const at = /^(?:messages|input)\\[(\\d+)\\]/.exec(entry.where || '');
    if (!at) continue;
    const index = Number(at[1]);
    if (!leaks.has(index)) leaks.set(index, []);
    leaks.get(index).push(entry);
  }
  return leaks;
}

// What a stand-in stands for: the kind of value, the rule that matched it,
// and the preview of the real value.
function valueTitle(entry) {
  return 'Masked ' + entry.kind + (entry.rule ? ', matched by ' + entry.rule : '') +
    '\\nReal value: ' + entry.preview;
}

// The kinds of mark as the page shows them, for the key and the folds.
const MARK_KINDS = [
  ['masked', 'mark[data-type=masked]', 'masked'],
  ['back', 'mark[data-back]', 'swapped back'],
  ['held', 'mark[data-type=held]', 'held back'],
];

// A key to the marks, with counts; a click goes to the next of that kind.
function renderLegend() {
  const viewer = byId('viewer');
  const keys = MARK_KINDS.flatMap(([type, selector, words]) => {
    const marks = [...viewer.querySelectorAll(selector)];
    if (marks.length === 0) return [];
    const key = byClass('button', 'key ' + type);
    key.append(byClass('mark', '', String(marks.length)), ' ' + words);
    key.dataset.type = type;
    let next = 0;
    key.addEventListener('click', () => {
      const mark = marks[next++ % marks.length];
      for (const at of viewer.querySelectorAll('mark.at')) at.classList.remove('at');
      void mark.offsetWidth;
      for (let open = mark.closest('details'); open; open = open.parentElement.closest('details'))
        open.open = true;
      mark.classList.add('at');
      mark.scrollIntoView({ block: 'center' });
    });
    return [key];
  });
  byId('legend').replaceChildren(...keys);
}

// The kept text laid out, at the top for a session just picked, where the
// reader was when a newer turn arrives, at the first match for a search.
function showText(place) {
  const text = texts.get(shownId);
  if (text === undefined) return;
  const viewer = byId('viewer');
  const needle = byId('detail_search').value.trim();
  const marks = marksFor(chosen);
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  const items = body && typeof body === 'object' ? turns(body) : [];
  const raw = view === 'raw' || items.length === 0;
  byId('view_chat').disabled = items.length === 0;
  for (const button of document.querySelectorAll('.view'))
    button.classList.toggle('on', button.dataset.view === (raw ? 'raw' : 'chat'));
  const fromBottom = viewer.scrollHeight - viewer.scrollTop;
  const atTop = viewer.scrollTop <= 4;
  viewer.classList.toggle('raw', raw);
  viewer.replaceChildren();
  let matches = 0;
  if (raw) {
    matches = markInto(viewer, text, marks.plain, needle);
  } else {
    const shown = conversation(items, marks, needle, leaksFor(chosen));
    viewer.append(...shown.nodes);
    matches = shown.matches;
  }
  byId('detail_count').textContent = needle ? plural(matches, 'match') : '';
  renderLegend();
  const first = needle ? viewer.querySelector('mark[data-type=found]') : null;
  if (first && place === 'find') {
    first.classList.add('at');
    first.scrollIntoView({ block: 'center' });
  } else if (place === 'top' || atTop) {
    viewer.scrollTop = 0;
  } else {
    viewer.scrollTop = viewer.scrollHeight - fromBottom;
  }
}

for (const button of document.querySelectorAll('.view'))
  button.addEventListener('click', () => {
    view = button.dataset.view;
    showText('top');
  });
byId('detail_search').addEventListener('input', () => showText('find'));
for (const section of document.querySelectorAll('.section')) {
  const key = 'ithildin.' + section.id;
  const saved = localStorage.getItem(key);
  if (saved !== null) section.open = saved === 'open';
  section.addEventListener('toggle', () =>
    localStorage.setItem(key, section.open ? 'open' : 'closed'));
}
offerNotifications();
poll();
setInterval(poll, POLL_MS);
setInterval(() => lastStats && renderStats(lastStats, lastWatch), 60000);
</script>
</body>
</html>
`;

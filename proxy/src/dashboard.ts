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
import { BODY_BYTES_MAX } from "./requests.ts";

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
    --mono: ui-monospace, monospace;
  }
  @media (prefers-color-scheme: light) {
    :root {
      --bg: #ebe9e4; --panel: #f6f5f1; --head: #e4e1da; --edge: #0000002e; --soft: #0000001a;
      --ink: #292826; --dim: #5a5750; --silver: #4a4843;
      --masked: #17469a; --masked_bg: #17469a1f;
      --swapped: #0b5f4a; --swapped_bg: #0b5f4a1f;
      --alert: #962718; --alert_bg: #9627181f;
      --quiet: #44413b; --quiet_bg: #0000001a;
      --find: #8a6400; --find_bg: #f2c94c66;
    }
  }
  * { box-sizing: border-box; }
  body {
    font: 14px/1.45 system-ui, sans-serif; color: var(--ink); background: var(--bg);
    margin: 0; height: 100vh; display: flex; flex-direction: column;
  }
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-thumb { background: var(--edge); border-radius: 4px; }
  button { font: inherit; color: inherit; }
  [hidden] { display: none !important; }

  /* The bar: is the proxy up, and did anything leak. */
  #bar {
    display: flex; align-items: center; gap: 22px; padding: 8px 20px;
    border-bottom: 1px solid var(--edge); box-shadow: 0 1px 0 var(--soft);
  }
  .brand { flex: none; }
  h1 {
    margin: 0 0 2px; font: 600 16px/1.2 system-ui, sans-serif; color: var(--silver);
  }
  h1 a { color: inherit; text-decoration: none; }
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
  #verdict b { display: block; font-size: 16px; font-weight: 600; }
  #verdict span { color: var(--dim); font-size: 12px; }
  #verdict.ok b { color: var(--silver); }
  #verdict.unwatched b { color: var(--dim); }
  #verdict.bad b { color: var(--alert); }
  .small {
    background: none; color: var(--dim); border: 1px solid var(--edge);
    border-radius: 3px; padding: 2px 8px; font-size: 12px; cursor: pointer;
  }
  .small:hover { color: var(--ink); }

  main {
    flex: 1; min-height: 0; display: grid; gap: 0;
    grid-template-columns: var(--side, 290px) 6px minmax(0, 1fr);
  }
  /* The handle between the sessions and the conversation: drag it, or focus
     it and use the arrow keys. */
  #grip { cursor: col-resize; overflow: hidden; border-left: 1px solid var(--edge); }
  #grip:hover, #grip:focus-visible, #grip.on { background: var(--soft); outline: none; }
  main > * { min-height: 0; overflow-y: auto; }
  h2 {
    display: flex; align-items: center; gap: 8px; margin: 18px 0 6px;
    font-size: 12px; font-weight: 600; color: var(--silver);
  }
  h2::after { content: ''; flex: 1; border-top: 1px solid var(--edge); }
  /* Every section of the left column folds the same way, and remembers it. */
  .section summary h2 { cursor: pointer; }
  .section summary:hover h2 { color: var(--ink); }
  .chev { order: 1; font-size: 10px; color: var(--dim); }
  .chev::before { content: '\\25be'; }
  .section:not([open]) .chev::before { content: '\\25b8'; }
  .section:not([open]) h2 { color: var(--dim); }

  /* Left: sessions, what to show, and the totals. */
  #side { padding: 0 14px 14px; }
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
  /* The totals, in three groups: busy, what it changed, what got through. */
  #numbers { display: flex; flex-direction: column; gap: 14px; margin-top: 12px; }
  #numbers .group h3 {
    margin: 0 0 6px; font-size: 11px; font-weight: 600; color: var(--dim);
  }
  #numbers .group h3::after {
    content: ''; display: block; margin-top: 4px; border-top: 1px solid var(--soft);
  }
  #numbers .group dl { margin-top: 0; }
  #num_masking #kinds { margin-bottom: 8px; }
  dl { display: grid; grid-template-columns: 1fr auto; gap: 3px 8px; margin: 0; font-size: 12px; }
  dt { color: var(--dim); }
  dd { margin: 0; text-align: right; }

  /* Middle: one card per request. */
  /* Main: the picked session, and its conversation as the provider saw it. */
  #center { display: flex; flex-direction: column; overflow: hidden; }
  #session_head { padding: 14px 18px 0; }
  #session_title {
    margin: 0; font: 600 17px/1.25 system-ui, sans-serif; color: var(--silver);
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
  /* One row whatever the request holds: wrapping as the legend and the note
     changed moved the conversation under the reader. */
  .find { display: flex; gap: 10px; align-items: center; padding: 10px 18px; }
  .find #legend { flex: 0 1 auto; min-width: 0; flex-wrap: nowrap; overflow-x: auto; }
  .find .key { white-space: nowrap; }
  .alert .more { margin-left: auto; flex: none; padding: 0 6px; font-size: 11px; }
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
  /* What leaked, read out of the body the page already shows. */
  mark[data-type=leak], .key.leak mark {
    background: var(--alert); color: var(--bg); outline-color: var(--alert);
  }
  @keyframes pulse {
    from { box-shadow: 0 0 0 5px var(--masked_bg); }
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
  .key:hover, .key.on { color: var(--ink); }
  .key.on { outline: 1px solid currentColor; }
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
  /* A leak named anywhere goes to its message on a click; the flag pulses. */
  .go, .badge.held { cursor: pointer; }
  .alert.go:hover { outline: 1px solid var(--alert); }
  @keyframes pulse_alert {
    from { box-shadow: 0 0 0 5px var(--alert_bg); }
    to { box-shadow: 0 0 0 0 transparent; }
  }
  .flag.at, .step.at, mark[data-type=leak].at { animation: pulse_alert 1.4s ease-out; }
  .empty { color: var(--dim); padding: 24px 0; text-align: center; }
  .empty b { display: block; color: var(--silver); font-size: 15px; }

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
  #viewer:not(.raw) { font: 12.5px/1.5 var(--mono); --label: 60px; }
  .step { display: flex; gap: 8px; margin: 0 0 8px; }
  details.step, .step.call { display: block; }
  /* A folded block says who it came from in the same column as a message. */
  details.step:not(.out) > summary { display: flex; gap: 8px; }
  details.step:not(.out) > .body { margin-left: calc(var(--label) + 8px); }
  /* Who said it, as a word in its own column: an arrow there read as
     something to click. */
  .glyph {
    flex: none; width: var(--label); color: var(--dim); font-size: 10.5px; line-height: 1.8;
    text-transform: uppercase; letter-spacing: .08em; user-select: none;
  }
  .said, .body { white-space: pre-wrap; overflow-wrap: anywhere; min-width: 0; }
  .step.prompt { padding: 6px 8px; border-radius: 4px; background: var(--head); }
  /* The timeline: each turn on a rail, a star where it starts. */
  .turn {
    margin-left: 6px; padding: 0 0 6px 16px; border-left: 1px solid var(--edge);
  }
  .turn.latest { border-left-color: var(--silver); }
  .turn_head {
    display: flex; align-items: center; gap: 8px; margin: 0 0 8px -22px; padding-top: 14px;
    font-size: 12px; font-weight: 600; color: var(--dim);
  }
  .turn:first-child .turn_head { padding-top: 0; }
  .turn:not([open]) .turn_head { padding-top: 6px; margin-bottom: 0; }
  .turn_head::before {
    content: '\\2022'; width: 11px; text-align: center; background: var(--panel);
    color: var(--dim); font-size: 11px;
  }
  .turn_head::after { content: ''; flex: 1; border-top: 1px solid var(--soft); }
  .turn.latest .turn_head, .turn.latest .turn_head::before {
    color: var(--silver);
  }
  /* A turn folds away on a click of its head; the chevron says it will. */
  .turn_head { cursor: pointer; }
  .turn_head:hover { color: var(--ink); }
  .turn_chev { font-size: 10px; }
  /* What the turn asked, in the reader's case: the head is caps, this is not. */
  .turn_gist, .turn_meta {
    font: 12px var(--mono); letter-spacing: 0; text-transform: none;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .turn_gist { min-width: 0; color: var(--ink); }
  /* An open turn shows its prompt in full; the head repeating it was noise. */
  .turn[open] .turn_gist { display: none; }
  .turn_meta { flex: none; }
  .turn_meta:empty { display: none; }
  /* A closed turn is one line, so the rail reads as a list of what was asked. */
  .turn:not([open]) { padding-bottom: 0; }
  .turn:not([open]) .turn_chev::before { content: '\\25b8'; }
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
  .held > summary .gist { color: var(--alert); }
  summary:hover .gist { color: var(--ink); }
  details.out { margin: 2px 0 0 1.6em; }
  .body {
    max-height: 320px; overflow: auto; margin: 4px 0 0; padding: 4px 10px;
    border-left: 1px solid var(--edge);
  }
  /* Chrome is not text anyone copies, and a drag across the page should not
     paint it. What is left selectable is what is worth copying: the
     conversation and the raw request, the figures, the kinds masked, and the
     alerts naming what was found. */
  header, #verdict, #notify, #session_title, #session_note, #side h2, #side h3,
  #side dt, .pick, .turn_head, summary, .glyph, .badge, .key, .count, .flag {
    user-select: none;
    -webkit-user-select: none;
  }

  @media (max-width: 700px) {
    main { display: flex; flex-direction: column; overflow-y: auto; }
    #side { border-right: 0; }
    #center { min-height: 80vh; }
    .find { flex-wrap: wrap; }
  }
</style>
</head>
<body>
<header id="bar">
  <div class="brand">
    <h1><a href="${DASHBOARD_PATH}" title="Back to the newest session">Ithildin</a></h1>
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
    <div id="numbers">
      <div class="group">
        <h3>Traffic</h3>
        <dl id="num_traffic"></dl>
      </div>
      <div class="group">
        <h3>Masking</h3>
        <div id="kinds"></div>
        <dl id="num_masking"></dl>
      </div>
      <div class="group">
        <h3>Safety</h3>
        <dl id="num_safety"></dl>
      </div>
      <div class="group">
        <h3>Shaping</h3>
        <dl id="num_shaping"></dl>
      </div>
      <div class="group">
        <h3>Cache</h3>
        <dl id="num_cache"></dl>
      </div>
    </div>
  </details>
</aside>
<div id="grip" role="separator" aria-orientation="vertical" aria-label="Resize the sessions"
  tabindex="0"></div>
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
// Request bodies held in the page. Each can be megabytes, so the page keeps
// the few it may show again rather than every one it has read.
const TEXTS_MAX = 4;
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
// What each of those requests masked, from the proxy, by the same id.
const values = new Map();
// The thinking of each one's reply so far, and whether the reply is over.
const replies = new Map();
// The thinking of earlier turns in each, from the replies the proxy kept.
const earlier = new Map();
// What the reader opened or closed, turns and folds alike, where it differs
// from how the page would set it: the view is rebuilt whenever a request
// arrives, and a rebuild must not undo a click.
const folds = new Map();
// Where the reader scrolled inside a long output, by the same keys, for the
// same reason.
const scrolls = new Map();
// The sessions in the order last laid out, kept while the pointer is on the
// list: sorted afresh each poll, a row moved out from under the click.
let sessionOrder = [];
// A rebuild held back while the reader has text selected in the conversation:
// it would drop the selection mid-copy. The next poll tries again.
let deferred = false;
// Whether the head lists every alert, or the newest alone.
let alertsOpen = false;
let shownId = 0;
// The request shown instead of the session's newest: the one a leak or a
// blocked call is in, until the reader picks a session or asks for the newest.
let pinned = 0;
let view = 'chat';
// Each session's shaping and cache figures, by the proxy's tally.
let tallies = {};
// The kind of mark the conversation is narrowed to, by its key in the legend.
let only;
// Stand-ins past MARKS_MAX in a text, counted by kind but not marked, so the
// legend tells the whole number.
let unmarked = {};

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

// A size the reader can place: the largest unit that keeps it at least one, so a
// session's savings read as 11.2 GiB rather than 11503.5 MiB.
function bytes(chars) {
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = chars / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return value.toFixed(1) + ' ' + units[unit];
}

// A guard's notice runs long; the full text is in the card's tooltip.
function firstSentence(text) {
  return text.split(/(?<=[.!?])\\s/)[0];
}

function leakDetail(entry) {
  const outcome = entry.action === 'block' ? 'request refused' : 'request sent anyway';
  const what = entry.kind === 'known' ? 'A value the proxy always masks' : 'A watched string';
  // The preview is cut like any real value: its first and last characters.
  const shape = /^(.*) \\((\\d+)\\)$/.exec(entry.preview || '');
  const shown = shape ? ', ' + shape[1] + ' (' + plural(Number(shape[2]), 'character') + '),'
    : '';
  return what + shown + ' found unmasked at ' + entry.where + ' (' + outcome + ')';
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

// The sessions, newest first like the turns; other traffic last.
function renderSessions() {
  const list = [...sessions.values()]
    .sort((a, b) => (a.id === OTHER) - (b.id === OTHER) || b.last - a.last);
  if (byId('sessions').matches?.(':hover')) {
    const place = new Map(sessionOrder.map((id, i) => [id, i]));
    list.sort((a, b) => (place.get(a.id) ?? place.size) - (place.get(b.id) ?? place.size));
  }
  sessionOrder = list.map((known) => known.id);
  const rows = list.map((known) => {
    const button = byClass('button', 'pick session' + (known.id === chosen ? ' on' : ''));
    const label = byClass('span', 'label');
    label.append(byClass('span', 'title', sessionLabel(known)),
      byClass('small', '', (known.title ? known.name + ' \\u00b7 ' : '') + clock(known.last)));
    button.appendChild(label);
    if (known.leaked > 0) {
      const leaks = byClass('span', 'badge held', String(known.leaked));
      leaks.title = plural(known.leaked, 'leak') + '; click to go to the latest';
      leaks.addEventListener('click', (event) => {
        event.stopPropagation();
        goTo(feed.find((entry) => entry.type === 'leaked' &&
          (entry.session || OTHER) === known.id));
      });
      button.appendChild(leaks);
    }
    button.title = known.id === OTHER ? 'Requests without a session, and refusals'
      : 'Session ' + known.id;
    button.addEventListener('click', () => choose(known.id));
    return button;
  });
  byId('sessions').replaceChildren(...rows);
  if (rows.length === 0) byId('sessions').appendChild(byClass('p', 'count', 'None yet'));
}

function choose(id, pin = 0) {
  chosen = id;
  pinned = pin;
  shownId = 0;
  // Turn numbers count a session's own turns, so another session's folds
  // are not this one's.
  folds.clear();
  scrolls.clear();
  renderSessions();
  return showSession();
}

// A leak or a blocked call, wherever it is named, leads to where it is: the
// request holding it shown, its turn opened, the place marked, pulsing and in
// view. The newest request often does not hold it: a subagent's or a side
// request's leak, a call blocked before the history was cleared. So the kept
// requests are searched, the one it happened in first. Found in none, it ends
// at the session.
async function goTo(entry) {
  if (!entry) return;
  const id = entry.session || OTHER;
  view = 'chat';
  only = undefined;
  const holding = await requestHolding(entry, id);
  if (id === chosen) {
    pinned = holding;
    shownId = 0;
    await showSession();
  } else {
    await choose(id, holding);
  }
  const spot = spotOf(byId('viewer'), entry);
  if (!spot) return;
  for (let open = spot.closest('details'); open; open = open.parentElement.closest('details'))
    open.open = true;
  spot.classList.remove('at');
  void spot.offsetWidth;
  spot.classList.add('at');
  spot.scrollIntoView({ block: 'center' });
}

// The node to show for an entry: a leak's own mark, else its flag; a blocked
// call's card.
function spotOf(viewer, entry) {
  if (entry.type === 'blocked')
    return entry.call ? viewer.querySelector('[data-call="' + entry.call + '"]') : null;
  return viewer.querySelector('mark[data-leak="' + entry.id + '"]') ||
    viewer.querySelector('.flag[data-leak="' + entry.id + '"]');
}

// The kept request of the session that holds an entry's place, or 0.
async function requestHolding(entry, id) {
  if (id === OTHER) return 0;
  const list = await (await fetch('${REQUESTS_PATH}', { cache: 'no-store' })).json();
  const own = (list.requests || []).filter((request) => request.session === id);
  const order = new Set([...own.filter((request) => request.turn === entry.turn),
    ...own.filter((request) => request.main), ...own]);
  for (const request of order) {
    if (!(await load(request.id))) continue;
    const body = parsed(texts.get(request.id));
    if (body && placeOf(entry, body)) return request.id;
  }
  return 0;
}

function parsed(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

// Where a leak or a blocked call is in a request body: the message it is in
// (-1 for the system prompt and tools), and for a leak the text that leaked,
// read out of the body by the place the proxy gave. Checked against the
// preview's first and last characters, so a later body that holds something
// else there is not taken for it. undefined: not in this body.
function placeOf(entry, body) {
  if (entry.type === 'blocked') {
    if (!entry.call) return undefined;
    const item = turns(body).find((each) => each.id === entry.call);
    return item && { at: item.at };
  }
  const value = valueAt(body, entry.where || '');
  if (typeof value !== 'string') return undefined;
  const at = /^(?:messages|input)\\[(\\d+)\\]/.exec(entry.where);
  const place = at ? Number(at[1]) : -1;
  if (entry.start === undefined) return { at: place, text: '' };
  const text = value.slice(entry.start, entry.start + entry.length);
  const shape = /^(.*)\\u2026(.*) \\((\\d+)\\)$/.exec(entry.preview || '');
  const fits = text.length === entry.length && (!shape ||
    (text.toLowerCase().startsWith(shape[1].toLowerCase()) &&
      text.toLowerCase().endsWith(shape[2].toLowerCase())));
  return fits ? { at: place, text } : undefined;
}

// The value at a place like messages[3].content[0].text.
function valueAt(body, where) {
  let value = body;
  for (const [, index, key] of where.matchAll(/\\[(\\d+)\\]|([^.[\\]]+)/g)) {
    if (!value || typeof value !== 'object') return undefined;
    value = value[index !== undefined ? Number(index) : key];
  }
  return value;
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
  const tally = tallyLine(tallies[known.id]);
  if (tally) note.append(byClass('br', ''), tally);
  const alarms = feed.filter((entry) => (entry.session || OTHER) === known.id &&
    (entry.type === 'leaked' || entry.type === 'blocked' || entry.type === 'refused'));
  // One line unless the reader asks for the rest: a list that grew with each
  // alert pushed the conversation down under the reader.
  const lines = alarms.slice(0, alertsOpen ? ALERTS_SHOWN : 1).map((entry) => {
    const line = byClass('div', 'alert');
    const what = entry.type === 'leaked' ? 'Leak' : entry.type === 'blocked' ? 'Blocked'
      : 'Refused ' + entry.status;
    const text = entry.type === 'leaked' ? leakDetail(entry) : entry.type === 'blocked'
      ? firstSentence(entry.text) : entry.text;
    line.append(byClass('span', 'when', clock(entry.time)), byClass('b', '', what), text);
    if (entry.text) line.title = entry.text;
    if (entry.type === 'leaked' || (entry.type === 'blocked' && entry.call)) {
      line.classList.add('go');
      line.title = entry.type === 'leaked' ? 'Go to the message it was found in'
        : 'Go to the call it stopped';
      line.addEventListener('click', () => goTo(entry));
    }
    return line;
  });
  if (alarms.length > 1) {
    const more = byClass('button', 'small more', alertsOpen ? 'fewer'
      : plural(alarms.length - 1, 'more alert'));
    more.addEventListener('click', (event) => {
      event.stopPropagation();
      alertsOpen = !alertsOpen;
      renderHead(known);
    });
    lines[0].append(more);
  }
  if (alertsOpen && alarms.length > ALERTS_SHOWN)
    lines.push(byClass('div', 'count', 'and ' + (alarms.length - ALERTS_SHOWN) + ' earlier'));
  byId('alerts').replaceChildren(...lines);
}
const ALERTS_SHOWN = 8;

// What shaping took off a session's requests and what its replies said the
// cache did, in a line; nothing for a session with neither.
function tallyLine(tally) {
  if (!tally) return '';
  const said = [];
  const shaped = tally.shapedMasked + tally.shapedCompacted + tally.shapedDeduped;
  if (shaped > 0) {
    const parts = [count(tally.shapedMasked) + ' stubbed'];
    if (tally.shapedCompacted) parts.push(count(tally.shapedCompacted) + ' compacted');
    if (tally.shapedDeduped) parts.push(count(tally.shapedDeduped) + ' repeats');
    said.push('Shaping: ' + parts.join(', ') + ', ' + bytes(tally.shapedSavedChars) + ' saved');
  }
  const read = tally.usageCacheRead;
  const prompt = tally.usageInput + read + tally.usageCacheWrite;
  if (prompt > 0) {
    said.push('Cache: ' + Math.round((read / prompt) * 100) + '% read of ' + count(prompt) +
      ' prompt tokens, ' + breakCounts(tally, ' / ', ' breaks'));
  }
  return said.join(' \\u00b7 ');
}

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
  note.append(byClass('b', '', 'No requests yet'),
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
  const sent = (pinned && own.find((request) => request.id === pinned)) ||
    own.find((request) => request.main) || own[0];
  if (!sent) {
    viewer.classList.add('raw');
    viewer.textContent = 'No request of this session is kept any more.';
    return;
  }
  if (sent.id === shownId) return;
  const selected = window.getSelection?.();
  deferred = shownId !== 0 && Boolean(selected && !selected.isCollapsed &&
    viewer.contains(selected.anchorNode));
  if (deferred) return;
  if (!(await load(sent.id))) return;
  if (chosen !== known.id) return;
  const first = shownId === 0;
  shownId = sent.id;
  const note = byId('view_note');
  note.textContent = 'As sent ' + clock(sent.time) +
    (sent.cut ? ', cut at ${BODY_BYTES_MAX / 1048576} MiB of ' + bytes(sent.size) : '');
  if (sent.id === pinned) {
    // Held on the request a leak or block is in: newer turns do not move it.
    const newest = byClass('button', 'small more', 'show newest');
    newest.addEventListener('click', () => {
      pinned = 0;
      shownId = 0;
      showSession();
    });
    note.append(', where it was found ', newest);
  }
  showText(first ? 'top' : 'keep');
}

// A kept request's text and masked values, fetched once. false: not kept.
async function load(id) {
  if (texts.has(id)) return true;
  const [response, masked] = await Promise.all([
    fetch('${REQUEST_PATH}?id=' + id, { cache: 'no-store' }),
    fetch('${REQUEST_PATH}?masked&id=' + id, { cache: 'no-store' }),
  ]);
  if (!response.ok) return false;
  texts.set(id, await response.text());
  values.set(id, masked.ok ? await masked.json() : []);
  // The page may show an older turn again, so the last few are kept.
  while (texts.size > TEXTS_MAX) {
    const oldest = texts.keys().next().value;
    texts.delete(oldest);
    values.delete(oldest);
    replies.delete(oldest);
    earlier.delete(oldest);
  }
  return true;
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
    if (last) tip = 'Latest in ' + last.where + '; click to go to it. ' + tip;
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
  verdict.classList.toggle('go', stats.leaked > 0);
  verdict.replaceChildren(byClass('b', '', title), byClass('span', '', note));
}

// A row per figure, its label and value: read down a group, not across it.
function figures(id, rows) {
  byId(id).replaceChildren(...rows.flatMap(([label, value]) =>
    [byClass('dt', '', label), byClass('dd', '', String(value))]));
}

// A count with its thousands grouped, so "1,240" is not read as four figures.
// A figure the proxy did not send reads as 0 rather than blanking the page.
function count(value) {
  return (Number(value) || 0).toLocaleString();
}

// The traffic since the proxy started, per minute.
function perMinute(stats) {
  const minutes = (Date.now() - stats.startedAt) / 60000;
  return minutes < 0.1 ? '-' : (stats.requests / minutes).toFixed(1) + ' /min';
}

// Three groups, each answering one question: how busy is it, what did it change,
// and did anything get through. A figure with nothing in it says so rather than
// showing a zero that looks like a measurement.
function renderStats(stats, watch) {
  renderVerdict(stats, watch);
  const kinds = Object.entries(stats.kinds).sort((a, b) => b[1] - a[1]);
  const most = kinds.length ? kinds[0][1] : 1;
  byId('kinds').replaceChildren(...kinds.map(([kind, hits]) => {
    const row = byClass('div', 'kind');
    const bar = byClass('i', '');
    bar.style.width = Math.max(4, Math.round((hits / most) * 100)) + '%';
    row.append(byClass('span', '', kind), byClass('span', '', count(hits)), bar);
    return row;
  }));
  if (kinds.length === 0) byId('kinds').appendChild(byClass('p', 'count', 'None yet'));
  const average = stats.requests ? Math.round((stats.scanMsTotal || 0) / stats.requests) : 0;
  const swapped = stats.swappedText + stats.swappedCalls;
  const route = Object.entries(stats.routes).sort((a, b) => b[1] - a[1])[0];
  figures('num_traffic', [
    ['Scanned', count(stats.requests)],
    ['Rate', perMinute(stats)],
    ['Busiest', route ? route[0] + ' (' + count(route[1]) + ')' : 'none'],
    ['Scan time', average + ' ms avg, ' + stats.scanMsMax + ' max'],
  ]);
  figures('num_masking', [
    ['Values masked', count(stats.replacements)],
    ['Distinct', count(stats.distinct)],
    ['Swapped back', swapped === 0 ? '0' : count(swapped) +
      ' (' + stats.swappedText + ' text, ' + stats.swappedCalls + ' calls)'],
  ]);
  figures('num_safety', [
    ['Leaks found', stats.leaked ? String(stats.leaked) : 'none'],
    ['Held back', String(stats.blocked)],
    ['Refused', String(stats.refused)],
  ]);
  // Shaping off the wire, and what it cost per request. "none yet" rather than
  // a zero: a proxy that has not shaped anything is not the same as one whose
  // sessions have all opted out, and only the badge tells those apart.
  const saved = stats.shapedSavedChars || 0;
  figures('num_shaping', [
    ['Saved', saved === 0 ? 'none yet' : bytes(saved)],
    ['Per request', stats.requests ? bytes(Math.round(saved / stats.requests)) : 'none yet'],
    ['Stubbed', count(stats.shapedMasked || 0)],
    ['Compacted', count(stats.shapedCompacted || 0)],
    ['Repeats', count(stats.shapedDeduped || 0)],
  ]);
  renderCache(stats);
}

// What the replies said the prompts cost, and how often a conversation's
// cached prefix broke. The share read from the cache is the figure that says
// Prefix breaks by whose doing; redaction's only when there were any, as a
// value learned late is the rare case.
function breakCounts(counts, joiner, tail) {
  const agent = counts.cacheBreaksAgent || 0;
  const redaction = counts.cacheBreaksRedaction || 0;
  const shaping = counts.cacheBreaksShaping || 0;
  if (agent + redaction + shaping === 0) return tail ? 'no breaks' : 'none';
  const said = [agent + ' agent'];
  if (redaction) said.push(redaction + ' redaction');
  said.push(shaping + ' shaping');
  return said.join(joiner) + tail;
}

// whether shaping's savings are real: a result already cached costs a tenth.
function renderCache(stats) {
  const read = stats.usageCacheRead || 0;
  const write = stats.usageCacheWrite || 0;
  const prompt = (stats.usageInput || 0) + read + write;
  figures('num_cache', [
    ['Read from cache', prompt ? Math.round((read / prompt) * 100) + '%' : 'no usage yet'],
    ['Prompt tokens', count(prompt) + ' (' + count(write) + ' written)'],
    ['Output tokens', count(stats.usageOutput || 0)],
    ['Prefix breaks', breakCounts(stats, ', ', '')],
    ['Last break', stats.lastBreak || 'none'],
  ]);
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
      replies.clear();
      earlier.clear();
      folds.clear();
      scrolls.clear();
      shownId = 0;
    }
    since = data.next;
    feed.unshift(...data.entries.slice().reverse());
    feed.length = Math.min(feed.length, FEED_MAX);
    noteEntries(data.entries);
    noteNames(data.sessions);
    lastStats = data.stats;
    lastWatch = data.watch;
    tallies = data.tallies || {};
    renderStats(data.stats, data.watch);
    alertTab(data.stats.leaked);
    // At first, the session that sent last; after that, the one picked.
    if (chosen === undefined || !sessions.has(chosen)) {
      const latest = [...sessions.values()].filter((known) => known.id !== OTHER)
        .sort((a, b) => b.last - a.last)[0];
      chosen = latest ? latest.id : sessions.has(OTHER) ? OTHER : undefined;
    }
    renderSessions();
    if (firstPoll || deferred ||
      data.entries.some((entry) => (entry.session || OTHER) === chosen))
      await showSession();
    await readThinking();
    if (!firstPoll) notifyLeaks(data.entries);
    firstPoll = false;
  } catch (error) {
    setState('proxy not answering', 'down');
  }
}

// The shown request's reply thinking, read again each poll until the reply is
// over, and laid out again when it grew.
async function readThinking() {
  const id = shownId;
  if (id && !earlier.has(id)) await readEarlier(id);
  const known = replies.get(id);
  if (!id || (known && known.done)) return;
  const response = await fetch('${REQUEST_PATH}?thinking&id=' + id, { cache: 'no-store' });
  if (!response.ok) return;
  const reply = await response.json();
  replies.set(id, reply);
  const grew = reply.text !== (known ? known.text : '');
  if (id === shownId && reply.text && (grew || reply.done)) showText('keep');
}

// Earlier turns' thinking, read once: those replies are over by the time the
// request is sent.
async function readEarlier(id) {
  const response = await fetch('${REQUEST_PATH}?earlier&id=' + id, { cache: 'no-store' });
  if (!response.ok) return;
  const found = await response.json();
  earlier.set(id, found);
  if (id === shownId && found.length > 0) showText('keep');
}

// Earlier turns' thinking the agent did not send back, each before the rest
// of the turn it came with. A turn that already has its thinking keeps it,
// and one the request no longer holds gets none.
function withEarlier(items, found) {
  if (!found || found.length === 0) return items;
  const out = items.slice();
  for (const { at, text } of found) {
    if (out.some((item) => item.at === at && item.kind === 'thinking')) continue;
    const place = out.findIndex((item) => item.at >= at);
    if (place >= 0) out.splice(place, 0, { who: 'assistant', kind: 'thinking', text, at });
  }
  return out;
}

// The reply's thinking after the request's own conversation, as the turn the
// agent is on. The request holds only earlier turns' thinking, and only what
// the agent sent back.
function withReply(items, reply) {
  if (!reply || !reply.text || items.length === 0) return items;
  // The tools offered carry no place; every other item does.
  const at = Math.max(-1, ...items.map((item) => item.at ?? -1)) + 1;
  return [...items,
    { who: 'assistant', kind: 'thinking', text: reply.text, at, live: !reply.done }];
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

// The stand-ins to mark, found by how each starts: a search of the text for
// every one was a pass per value, which a long session's thousands of them
// made too slow to keep them all. Built once per set of marks.
const PREFIX_CHARS = 4;
const wantIndexes = new WeakMap();
function wantIndex(wants) {
  let index = wantIndexes.get(wants);
  if (index) return index;
  index = { byPrefix: new Map(), short: [] };
  const longest = wants.filter((want) => want.text).sort((a, b) => b.text.length - a.text.length);
  for (const want of longest) {
    if (want.text.length < PREFIX_CHARS) {
      index.short.push(want);
      continue;
    }
    const prefix = want.text.slice(0, PREFIX_CHARS);
    if (!index.byPrefix.has(prefix)) index.byPrefix.set(prefix, []);
    index.byPrefix.get(prefix).push(want);
  }
  wantIndexes.set(wants, index);
  return index;
}

// A stand-in is marked only where it stands whole, as the engine matches a
// value: a short one is inside plenty of words, and marking those reads as if
// the word had been masked.
const WORD_CHAR = /[\\p{L}\\p{N}_]/u;
function standsWhole(text, at, length) {
  const word = (char) => char !== undefined && WORD_CHAR.test(char);
  const end = at + length;
  return !(word(text[at - 1]) && word(text[at])) && !(word(text[end - 1]) && word(text[end]));
}

// Where the stand-ins are in a text: the earliest first, the longest of
// those starting at the same place, none inside another or inside a word.
function standInsIn(text, wants) {
  const index = wantIndex(wants);
  const found = [];
  const fits = (want, at) =>
    text.startsWith(want.text, at) && (want.loose || standsWhole(text, at, want.text.length));
  for (let at = 0; at < text.length; at++) {
    let hit = (index.byPrefix.get(text.slice(at, at + PREFIX_CHARS)) || [])
      .find((want) => fits(want, at));
    for (const want of index.short)
      if (fits(want, at) && want.text.length > (hit ? hit.text.length : 0)) hit = want;
    if (!hit) continue;
    const end = at + hit.text.length;
    found.push({ at, end, type: hit.type, title: hit.title, back: hit.back, leak: hit.leak });
    at = end - 1;
  }
  return found;
}

// The text in a node, with each stand-in of the card and each match of the
// search marked, as plain text nodes. Returns how many search matches.
function markInto(node, text, wants, needle) {
  const found = standInsIn(text, wants);
  let matches = 0;
  if (needle) {
    const lower = text.toLowerCase();
    const what = needle.toLowerCase();
    for (let at = lower.indexOf(what); at >= 0; at = lower.indexOf(what, at + what.length)) {
      matches++;
      if (matches <= MARKS_MAX) found.push({ at, end: at + what.length, type: 'found' });
    }
  }
  found.sort((a, b) => a.at - b.at || b.end - a.end);
  let from = 0;
  let shown = 0;
  for (const hit of found) {
    if (hit.at < from) continue;
    // Past the cap a mark is counted, not drawn: thousands of marks make the
    // page slow to lay out, and the reader wants the number, not each one.
    if (shown++ >= MARKS_MAX) {
      unmarked[hit.type] = (unmarked[hit.type] || 0) + 1;
      if (hit.back) unmarked.back = (unmarked.back || 0) + 1;
      continue;
    }
    node.append(text.slice(from, hit.at));
    const mark = document.createElement('mark');
    mark.textContent = text.slice(hit.at, hit.end);
    mark.dataset.type = hit.type;
    if (hit.title) mark.title = hit.title;
    if (hit.back) mark.dataset.back = '';
    if (hit.leak) mark.dataset.leak = String(hit.leak);
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
function fold(className, head, text, wants, needle, label) {
  const box = byClass('details', 'step ' + className);
  const summary = document.createElement('summary');
  if (label !== undefined) summary.appendChild(byClass('span', 'glyph', label));
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
  // Text that is only the proxy's notice of what it held back, a blocked
  // call's result most often, says so in its head, red, and stays shut:
  // opened, it said the same thing again under it.
  const held = body.querySelector('mark[data-type=held]');
  const notice = held !== null && text.trimStart().startsWith(held.textContent) &&
    body.querySelector('mark:not([data-type=masked]):not([data-type=held])') === null;
  if (notice) box.classList.add('held');
  box.open = !notice && body.querySelector('mark:not([data-type=masked])') !== null;
  return { node: box, matches, fold: box };
}

// A fold as the reader last left it, unless the search has a match inside:
// that opens it. Only a choice that differs from the page's own is kept, so
// a turn the reader never touched closes once a newer one arrives.
function remember(box, key) {
  const body = box.querySelector(':scope > .body');
  if (body) {
    body.dataset.key = key;
    body.addEventListener('scroll', () => scrolls.set(key, body.scrollTop));
  }
  const usual = box.open;
  const found = box.querySelector('mark[data-type=found]') !== null;
  if (folds.has(key) && !found) box.open = folds.get(key);
  box.addEventListener('toggle', () => {
    if (box.open === usual) folds.delete(key);
    else folds.set(key, box.open);
  });
}

// Who a block the harness wrapped in a tag came from: what the reader ran
// with "!" or a slash command is theirs, its output the shell's, and the
// rest (reminders, notices) the harness's own.
function speaker(tag) {
  if (/^(bash-input|command-)/.test(tag)) return 'you';
  if (/(stdout|stderr)$/.test(tag)) return 'shell';
  return 'harness';
}

// A wrapped block's head: its tag, then the first line inside it.
function wrapped(tag, text) {
  const inner = text.replace(/<\\/?[a-z][\\w-]*[^>]*>/g, ' ').trim();
  return inner ? tag + '  ' + oneLine(inner, 100) : tag;
}

function said(className, glyph, text, wants, needle) {
  const box = byClass('div', 'step ' + className);
  const words = byClass('div', 'said');
  const matches = markInto(words, text, wants, needle);
  box.append(byClass('span', 'glyph', glyph), words);
  return { node: box, matches };
}

// The conversation newest first, turns and the messages in them alike, like
// a feed: each message labelled with who said it (you, agent, tool), a call's
// result folded under it after "\\u23bf", and the system prompt, the tools
// and harness text folded. Only the newest turn is open; a closed turn's head
// says what was asked and how many calls it took, so the closed ones still
// read. The model's own words get
// the marks that say which stand-ins came back to it real; a leak is flagged
// on the message it was found in.
function conversation(items, marks, needle, leaks) {
  const results = new Map();
  for (const item of items)
    if (item.kind === 'tool_result' && item.id) results.set(item.id, item);
  const paired = new Set();
  const flagged = new Set();
  // A turn starts at each message holding something the user typed, not a
  // reminder or a tool result beside one. Each turn hangs on a rail.
  // Its title is what was typed there: the message's first item is often the
  // tool result or reminder the harness put beside it.
  const prompts = new Map();
  for (const item of items)
    if (item.kind === 'user' && !WRAPPED.test(item.text) && !prompts.has(item.at))
      prompts.set(item.at, item.text);
  // A note the harness repeats between steps, a token count after every
  // result, shows once a turn: one each time buried the steps between them.
  // Known by its text with the figures taken out.
  let notes = new Set();
  const nodes = [];
  const calls = [];
  const repeats = [];
  const metas = [];
  // What each turn holds, kept apart until the end so it can go in newest
  // first; a leak's flag stays above the message it is about.
  const groups = [];
  let turn;
  let count = 0;
  let started = -2;
  // Folds are known by where their message sits, which a later request of the
  // same conversation leaves alone, so a rebuild finds the reader's choices.
  const seen = new Map();
  const start = (title, asked) => {
    turn = document.createElement('details');
    turn.className = 'turn';
    const head = byClass('summary', 'turn_head', title);
    if (asked) head.appendChild(byClass('span', 'turn_gist', oneLine(asked, 120)));
    const meta = byClass('span', 'turn_meta');
    head.append(meta, byClass('span', 'chev turn_chev'));
    metas.push(meta);
    turn.appendChild(head);
    nodes.push(turn);
    groups.push([]);
    calls.push(0);
    repeats.push(0);
  };
  let matches = 0;
  // also: the messages of a result shown under its call, whose leaks are
  // flagged on the call's card.
  const put = (item, shown, also = []) => {
    if (!turn) start('Before the first prompt');
    const group = [];
    for (const at of [item.at, ...also]) {
      const found = leaks.get(at);
      if (!found || flagged.has(at)) continue;
      flagged.add(at);
      for (const { entry, text } of found) {
        const what = text ? '\\u201c' + oneLine(text, 80) + '\\u201d \\u00b7 ' : '';
        const flag = byClass('div', 'flag', '\\u26a0 Leak: ' + what + leakDetail(entry));
        flag.dataset.at = String(at);
        flag.dataset.leak = String(entry.id);
        group.push(flag);
      }
    }
    if (item.id) shown.node.dataset.call = item.id;
    group.push(shown.node);
    groups[groups.length - 1].push(group);
    matches += shown.matches;
    const nth = seen.get(item.at) || 0;
    seen.set(item.at, nth + 1);
    if (shown.fold) remember(shown.fold, item.at + ':' + nth);
  };
  const plain = marks.plain;
  const model = marks.model;
  for (const item of items) {
    if (prompts.has(item.at) && item.at !== started) {
      started = item.at;
      start('Turn ' + ++count, prompts.get(item.at));
      notes = new Set();
    }
    if (item.kind === 'tools') {
      put(item, fold('meta', item.name + ' tools offered', item.text, plain, needle, 'system'));
    } else if (item.kind === 'system') {
      const note = item.at >= 0;
      const shape = item.text.replace(/\\d+/g, '#');
      if (note && notes.has(shape)) {
        repeats[repeats.length - 1]++;
        continue;
      }
      if (note) notes.add(shape);
      const size = item.text.length + ' characters';
      const head = (note ? 'System note' : 'System prompt') + ' \\u00b7 ' + size;
      put(item, fold('meta', head, item.text, plain, needle, 'system'));
    } else if (item.kind === 'user') {
      const tag = WRAPPED.exec(item.text);
      if (tag) put(item, fold('meta', wrapped(tag[1], item.text), item.text, plain, needle,
        speaker(tag[1])));
      else put(item, said('prompt', 'you', item.text, plain, needle));
    } else if (item.kind === 'assistant') {
      put(item, said('reply', 'agent', item.text, model, needle));
    } else if (item.kind === 'thinking') {
      // Its first line in the head, a reasoning summary's title most often:
      // a bare "Thinking" between every call said nothing.
      const gist = oneLine(item.text.replace(/\\*\\*/g, '').split('\\n')[0], 100);
      const head = item.live ? 'Thinking \\u00b7 live'
        : gist && !/^\\(hidden/.test(gist) ? 'Thinking \\u00b7 ' + gist : 'Thinking';
      put(item, fold('meta', head, item.text, plain, needle, 'agent'));
    } else if (item.kind === 'tool_call') {
      const result = item.id ? results.get(item.id) : undefined;
      if (result) paired.add(result);
      const gist = brief(item);
      const box = byClass('div', 'step call');
      const head = byClass('div', 'head');
      const args = byClass('span', 'args');
      matches += markInto(args, '(' + gist.text + ')', model, needle);
      head.append(byClass('span', 'glyph', 'tool'), byClass('b', '', item.name || 'tool'), args);
      const output = result ? result.text : '';
      const lines = output.split('\\n');
      const first = output ? oneLine(lines[0], 90) : '(no output)';
      const more = lines.length > 1 ? '  \\u2026 +' + (lines.length - 1) + ' lines' : '';
      const body = (gist.more ? item.text + '\\n\\n' : '') + output;
      const shown = fold('out', '\\u23bf  ' + first + more, body, plain, needle);
      matches += shown.matches;
      box.append(head, shown.node);
      put(item, { node: box, matches: 0, fold: shown.fold }, result ? [result.at] : []);
      calls[calls.length - 1]++;
    } else if (item.kind === 'tool_result') {
      if (paired.has(item)) continue;
      put(item, fold('out', '\\u23bf  ' + oneLine(item.text, 90), item.text, plain, needle));
    } else if (item.kind === 'media') {
      put(item, said('media', '', item.text, plain, needle));
    } else {
      put(item, fold('meta', item.kind, item.text, plain, needle, item.who));
    }
  }
  nodes.forEach((node, index) => {
    for (const group of groups[index].reverse()) node.append(...group);
    const latest = index === nodes.length - 1;
    const said = [];
    if (calls[index] > 0) said.push(plural(calls[index], 'tool call'));
    if (repeats[index] > 0) said.push(plural(repeats[index], 'repeated note') + ' hidden');
    if (latest && count > 0) said.push('latest');
    metas[index].textContent = said.join(' \\u00b7 ');
    if (latest && count > 0) node.classList.add('latest');
    // An older turn opens when the search found something in it.
    node.open = latest || node.querySelector('mark[data-type=found]') !== null;
    remember(node, 'turn ' + (index + 1));
  });
  // Newest first, turns and what is in them, so what just happened is on top.
  return { nodes: nodes.reverse(), matches };
}

// The left column's width, which the reader sets by dragging the handle or
// with the arrow keys on it, kept between visits. It stays wide enough for a
// session's name and narrow enough to leave the conversation room.
const SIDE_MIN = 180;
const SIDE_MAX = 560;
function resizable(grip) {
  const main = grip.parentElement;
  const set = (width) => {
    const px = Math.round(Math.min(SIDE_MAX, Math.max(SIDE_MIN, width)));
    main.style.setProperty('--side', px + 'px');
    grip.setAttribute('aria-valuenow', String(px));
    return px;
  };
  let width = set(Number(localStorage.getItem('ithildin.side')) || 290);
  const keep = () => localStorage.setItem('ithildin.side', String(width));
  grip.addEventListener('pointerdown', (event) => {
    event.preventDefault();
    grip.setPointerCapture(event.pointerId);
    grip.classList.add('on');
    const left = main.getBoundingClientRect().left;
    const move = (moved) => (width = set(moved.clientX - left));
    const done = () => {
      grip.classList.remove('on');
      grip.removeEventListener('pointermove', move);
      grip.removeEventListener('pointerup', done);
      keep();
    };
    grip.addEventListener('pointermove', move);
    grip.addEventListener('pointerup', done);
  });
  grip.addEventListener('keydown', (event) => {
    const step = event.key === 'ArrowLeft' ? -20 : event.key === 'ArrowRight' ? 20 : 0;
    if (step === 0) return;
    event.preventDefault();
    width = set(width + step);
    keep();
  });
  grip.addEventListener('dblclick', () => {
    width = set(290);
    keep();
  });
}

// What to mark in a session's conversation: the stand-ins the proxy made,
// and what it held back (a guard's refusal, a withheld file or image). In
// the model's own words, a stand-in it used that came back real is marked so.
function marksFor(id, masked = []) {
  const back = new Map();
  const known = new Map();
  // The request's own values first: every one it masked, however many, where
  // the feed has only the newest across all sessions.
  for (const value of masked) if (!known.has(value.standIn)) known.set(value.standIn, value);
  // The session's own first, so a value of its own is never crowded out.
  const own = (entry) => (entry.session || OTHER) === id;
  for (const entry of feed.filter(own).concat(feed.filter((entry) => !own(entry)))) {
    if (!entry.standIn) continue;
    if (entry.type === 'swapped' && own(entry)) {
      if (!back.has(entry.standIn)) back.set(entry.standIn, new Set());
      back.get(entry.standIn).add(entry.where === 'reply text' ? 'the reply' : entry.where);
    }
    if (!known.has(entry.standIn)) known.set(entry.standIn, entry);
  }
  const held = new Map(HELD_NOTICES.map((text) => [text, 'The proxy held this back']));
  for (const entry of feed)
    if (entry.type === 'blocked') held.set(firstSentence(entry.text), entry.text);
  const heldMarks = [...held].map(([text, title]) => ({ text, type: 'held', title }));
  // A home directory's stand-in is its path with the user swapped, so only the
  // user is marked: the rest is the real path, never masked.
  const value = ([text, entry]) => ({
    text: entry.kind === 'home' ? text.slice(text.search(/[^\\\\/]*$/)) : text,
    type: 'masked', title: valueTitle(entry),
  });
  const plain = [...known].map(value);
  const model = [...known].map(([text, entry]) => !back.has(text) ? value([text, entry]) : {
    ...value([text, entry]), back: true,
    title: valueTitle(entry) + '\\nThe model used it, and the proxy put the real value back in ' +
      [...back.get(text)].join(', ') + '.',
  });
  return { plain: plain.concat(heldMarks), model: model.concat(heldMarks) };
}

// Each leak of a session this body holds, by the message it is in, with the
// text that leaked; and that text as marks, red wherever it stands.
function leaksFor(id, body) {
  const leaks = new Map();
  const wants = [];
  for (const entry of feed) {
    if (entry.type !== 'leaked' || (entry.session || OTHER) !== id) continue;
    const place = body && placeOf(entry, body);
    if (!place) continue;
    if (!leaks.has(place.at)) leaks.set(place.at, []);
    leaks.get(place.at).push({ entry, text: place.text });
    if (place.text)
      wants.push({ text: place.text, type: 'leak', loose: true, leak: entry.id,
        title: 'Leaked: ' + leakDetail(entry) });
  }
  return { leaks, wants };
}

// What a stand-in stands for: the kind of value, the rule that matched it,
// and the preview of the real value.
function valueTitle(entry) {
  const shape = /^(.*) \\((\\d+)\\)$/.exec(entry.preview || '');
  const real = shape ? shape[1] + ', ' + plural(Number(shape[2]), 'character') : entry.preview;
  return (VALUE_KINDS[entry.kind] || entry.kind) + ', masked' +
    '\\nThe model sees this stand-in; the real value stays on this machine.' +
    (real ? '\\nReal value: ' + real : '') +
    (entry.rule ? '\\nFound by rule ' + entry.rule : '');
}

// The kinds a stand-in can be (aliasKind, and kindOf's secret), in words.
const VALUE_KINDS = {
  email: 'Email address',
  host: 'Host name',
  'user-at-host': 'User at host',
  user: 'User name',
  home: 'Home directory',
  ipv4: 'IP address',
  ipv6: 'IPv6 address',
  mac: 'MAC address',
  label: 'Personal detail',
  secret: 'Secret',
};

// The kinds of mark as the page shows them, for the key and the folds.
const MARK_KINDS = [
  ['masked', 'mark[data-type=masked]', 'masked'],
  ['back', 'mark[data-back]', 'swapped back'],
  ['held', 'mark[data-type=held]', 'held back'],
  ['leak', 'mark[data-type=leak]', 'leaked'],
];

// A key to the marks, with counts. In the conversation a click narrows it to
// the messages holding that kind and a second click shows all again; in the
// raw text, which has no messages, it goes to the next of that kind.
function renderLegend(raw, beyond = []) {
  const viewer = byId('viewer');
  if (raw || !MARK_KINDS.some(([type, selector]) =>
    type === only && viewer.querySelector(selector))) only = undefined;
  const keys = MARK_KINDS.flatMap(([type, selector, words]) => {
    const marks = [...viewer.querySelectorAll(selector)];
    if (marks.length === 0) return [];
    const key = byClass('button', 'key ' + type + (type === only ? ' on' : ''));
    const over = unmarked[type] || 0;
    key.append(byClass('mark', '', String(marks.length + over)), ' ' + words +
      (over ? ' (first ' + marks.length + ' marked)' : ''));
    key.dataset.type = type;
    key.title = raw ? 'Go to the next' : 'Show only the messages with these';
    let next = 0;
    key.addEventListener('click', () => {
      if (!raw) {
        only = only === type ? undefined : type;
        for (const other of byId('legend').children)
          other.classList.toggle('on', other.dataset.type === only);
        narrow(viewer);
        viewer.scrollTop = 0;
        return;
      }
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
  const notes = beyond.map(({ count, field }) =>
    byClass('span', 'count', '+' + count + ' in ' + field + ', outside the messages'));
  byId('legend').replaceChildren(...keys, ...notes);
  narrow(viewer);
}

// Stand-ins in the parts of a request the conversation does not show, such as
// the metadata an agent sends for the provider's own checks: the raw view
// marks them, so without a note its count and the conversation's disagree.
const SHOWN_FIELDS = ['system', 'instructions', 'messages', 'input'];

function outside(body, wants) {
  if (!body || typeof body !== 'object') return [];
  return Object.keys(body).flatMap((field) => {
    if (SHOWN_FIELDS.includes(field)) return [];
    const count = standInsIn(JSON.stringify(body[field]) || '', wants).length;
    return count ? [{ count, field }] : [];
  });
}

// The conversation narrowed to the legend's kind: a message without one is
// hidden, and a turn without one too. Folds stay as the reader left them, so
// clearing the filter puts back what was there before.
function narrow(viewer) {
  const kind = MARK_KINDS.find(([type]) => type === only);
  for (const turn of viewer.querySelectorAll(':scope > details.turn')) {
    let any = false;
    for (const child of [...turn.children].slice(1)) {
      const keep = !kind || child.querySelector(kind[1]) !== null;
      child.hidden = !keep;
      any = any || keep;
    }
    turn.hidden = !any;
  }
}

// The kept text laid out, at the top for a session just picked, where the
// reader was when a newer turn arrives, at the first match for a search.
function showText(place) {
  const text = texts.get(shownId);
  if (text === undefined) return;
  const viewer = byId('viewer');
  const needle = byId('detail_search').value.trim();
  const marks = marksFor(chosen, values.get(shownId) || []);
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  const items = body && typeof body === 'object'
    ? withReply(withEarlier(turns(body), earlier.get(shownId)), replies.get(shownId)) : [];
  const raw = view === 'raw' || items.length === 0;
  byId('view_chat').disabled = items.length === 0;
  for (const button of document.querySelectorAll('.view'))
    button.classList.toggle('on', button.dataset.view === (raw ? 'raw' : 'chat'));
  // The newest is on top, so a reader there sees it arrive, and one who
  // scrolled down to read stays on what they were reading: what arrives
  // lands above them, and the scroll moves by as much.
  const atTop = viewer.scrollTop <= 24;
  const below = viewer.scrollHeight - viewer.scrollTop;
  viewer.classList.toggle('raw', raw);
  viewer.replaceChildren();
  unmarked = {};
  let matches = 0;
  if (raw) {
    matches = markInto(viewer, text, marks.plain, needle);
  } else {
    const { leaks, wants } = leaksFor(chosen, body);
    const all = { plain: marks.plain.concat(wants), model: marks.model.concat(wants) };
    const shown = conversation(items, all, needle, leaks);
    viewer.append(...shown.nodes);
    matches = shown.matches;
    for (const body of viewer.querySelectorAll('.body[data-key]'))
      if (scrolls.has(body.dataset.key)) body.scrollTop = scrolls.get(body.dataset.key);
  }
  byId('detail_count').textContent = needle ? plural(matches, 'match') : '';
  renderLegend(raw, raw ? [] : outside(body, marks.plain));
  const first = needle ? viewer.querySelector('mark[data-type=found]') : null;
  if (first && place === 'find') {
    first.classList.add('at');
    first.scrollIntoView({ block: 'center' });
  } else if (place === 'top' || atTop) {
    viewer.scrollTop = 0;
  } else {
    viewer.scrollTop = viewer.scrollHeight - below;
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
resizable(byId('grip'));
// Off the list, it takes the newest-first order again.
byId('sessions').addEventListener('mouseleave', renderSessions);
byId('verdict').addEventListener('click', () =>
  goTo(feed.find((entry) => entry.type === 'leaked')));
offerNotifications();
poll();
setInterval(poll, POLL_MS);
setInterval(() => lastStats && renderStats(lastStats, lastWatch), 60000);
</script>
</body>
</html>
`;

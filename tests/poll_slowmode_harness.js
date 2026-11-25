// Runs functions of static/watch.html and static/chat.html under Node against a small fake page: the poll card
// keeps the viewer's own choice across a broadcast, and the slow mode select returns to the last confirmed value
// when the server refuses a change. No browser: the look of the page and a real socket are not covered.
// Used by tests/test_poll_slowmode.py.
//
// usage: node poll_slowmode_harness.js <path to watch.html> <path to chat.html>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const watchHtml = fs.readFileSync(process.argv[2], 'utf8');
const chatHtml = fs.readFileSync(process.argv[3], 'utf8');
// One function (plain or async) by name, cut at its closing brace.
function fn(html, name) {
  let a = html.indexOf('async function ' + name + '(');
  if (a < 0) a = html.indexOf('function ' + name + '(');
  if (a < 0) throw new Error('function not found: ' + name);
  let i = html.indexOf('{', html.indexOf(')', a));
  let depth = 0;
  for (; i < html.length; i++) {
    if (html[i] === '{') depth++;
    else if (html[i] === '}' && --depth === 0) return html.slice(a, i + 1);
  }
  throw new Error('unbalanced: ' + name);
}
// A page without a helper still loads, so the checks fail on behaviour instead of on a missing name
function opt(html, name, fallback) { try { return fn(html, name); } catch (e) { return fallback; } }
function optLine(html, re, fallback) { const m = html.match(re); return m ? m[0] : fallback; }
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }
async function withDeadline(name, f, ms) {
  let timer;
  const late = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('no answer within ' + (ms || 5000) + ' ms')), ms || 5000); });
  try { await Promise.race([f(), late]); } catch (e) { check(name + ' (did not finish)', false, e && e.message); } finally { clearTimeout(timer); }
}

// ---- watch.html -------------------------------------------------------------------------------------------
// A minimal element: enough for buildPollElement, updatePollElement and the select.
function el(tag) {
  const e = { tag, children: [], className: '', dataset: {}, listeners: {}, style: {}, disabled: false, type: '', _text: '', value: '' };
  Object.defineProperty(e, 'textContent', { get() { return e._text; }, set(v) { e._text = String(v); } });
  e.appendChild = (c) => { e.children.push(c); c.parent = e; return c; };
  e.append = (...cs) => cs.forEach((c) => e.appendChild(c));
  e.addEventListener = (n, f) => { e.listeners[n] = f; };
  e.replaceWith = (n) => { if (e.parent) { const i = e.parent.children.indexOf(e); e.parent.children[i] = n; n.parent = e.parent; } e.replaced = n; };
  return e;
}
function walk(e, f) { f(e); (e.children || []).forEach((c) => walk(c, f)); }

function watchWorld() {
  const root = el('div');
  const sent = [];
  const slow = el('select'); slow.value = '0';
  const sandbox = {
    document: {
      createElement: el,
      getElementById: (id) => (id === 'slowmode-select' ? slow : null),
      querySelector: (sel) => {
        const m = sel.match(/data-poll-id="([^"]*)"/);
        let found = null;
        walk(root, (e) => { if (!found && m && e.className === 'watch-poll' && String(e.dataset.pollId) === m[1]) found = e; });
        return found;
      },
    },
    CSS: { escape: (s) => s },
    WebSocket: { OPEN: 1 },
    chatWs: { readyState: 1, send: (s) => sent.push(JSON.parse(s)) },
    modLevel: 'none', currentUser: { id: 9 },
    appendSystemMessage() {},
    console,
  };
  vm.createContext(sandbox);
  const code = [
    optLine(watchHtml, /const pollMine = [^\n]*;/, 'const pollMine = new Map();'),
    optLine(watchHtml, /const slowmodeState = [^\n]*;/, 'const slowmodeState = {};'),
    opt(watchHtml, 'revertSlowmode', 'function revertSlowmode() {}'),
    opt(watchHtml, 'isModLevel', 'function isModLevel() { return false; }'),
    fn(watchHtml, 'buildPollElement'), fn(watchHtml, 'updatePollElement'),
    opt(watchHtml, 'setSlowmodeSelect', 'function setSlowmodeSelect() {}'), opt(watchHtml, 'setSlowmode', 'function setSlowmode() {}'),
    // the 'error' and 'slowmode_changed' branches of the frame handler, cut from the page
    'this.api = { build: buildPollElement, update: updatePollElement, setSelect: setSlowmodeSelect, setSlowmode, setSlowmodeSelect };',
  ].join('\n');
  vm.runInContext(code, sandbox);
  return { sandbox, root, sent, slow, api: sandbox.api };
}
function options(box) { const o = []; walk(box, (e) => { if ((e.className || '').startsWith('watch-poll-option')) o.push(e); }); return o; }
function mineIdx(box) { return options(box).map((e, i) => (e.className.includes('mine') ? i : -1)).filter((i) => i >= 0); }
function pollFrame(extra) { return Object.assign({ id: 4, question: 'q', options: ['a', 'b', 'c'], votes: { 0: 1, 1: 0, 2: 0 }, total_votes: 1, allow_multiple: 0, is_closed: 0, user_id: 1, my_votes: [] }, extra || {}); }

// The 'error' branch of watch.html's frame handler, run as the page runs it: find the case and evaluate it
function watchErrorBranch() {
  const a = watchHtml.indexOf("case 'error':");
  if (a < 0) throw new Error("case 'error' not found");
  const b = watchHtml.indexOf('break;', a);
  return watchHtml.slice(a + "case 'error':".length, b);
}

(async () => {
  await withDeadline('watch: highlight kept', async () => {
    const w = watchWorld();
    const box = w.api.build(pollFrame({ my_votes: [1] }));
    w.root.appendChild(box);
    check('a poll built with my_votes shows the choice', mineIdx(box).join() === '1', mineIdx(box));
    w.api.update(pollFrame({ votes: { 0: 2, 1: 0, 2: 0 }, total_votes: 2, my_votes: [] }));   // another member's vote: no my_votes
    const now = w.root.children[0];
    check('a poll_updated frame without my_votes keeps the choice', mineIdx(now).join() === '1', mineIdx(now));
    check('the counts follow the frame', options(now)[0].children[1].textContent === '2');
    w.api.update(pollFrame({ votes: { 0: 2, 1: 1, 2: 0 }, total_votes: 3, my_votes: [2] }));  // a frame that does carry the choice wins
    check('a frame that carries my_votes replaces the kept choice', mineIdx(w.root.children[0]).join() === '2', mineIdx(w.root.children[0]));
    const other = w.api.build(pollFrame({ id: 5 }));
    check('another poll does not take the kept choice', mineIdx(other).length === 0, mineIdx(other));
  });
  await withDeadline('watch: own click', async () => {
    const w = watchWorld();
    const box = w.api.build(pollFrame({ my_votes: [0] }));
    w.root.appendChild(box);
    options(box)[2].listeners.click();
    check('the click sends the vote', w.sent.length === 1 && w.sent[0].type === 'vote_poll' && w.sent[0].option_index === 2, JSON.stringify(w.sent));
    w.api.update(pollFrame({ my_votes: [], votes: { 0: 0, 1: 0, 2: 1 }, total_votes: 1 }));
    check('after a vote in a single-choice poll the broadcast shows the new choice only', mineIdx(w.root.children[0]).join() === '2', mineIdx(w.root.children[0]));
    const m = watchWorld();
    const mbox = m.api.build(pollFrame({ id: 6, allow_multiple: 1, my_votes: [0] }));
    m.root.appendChild(mbox);
    options(mbox)[2].listeners.click();
    m.api.update(pollFrame({ id: 6, allow_multiple: 1, my_votes: [] }));
    check('after a vote in a multiple-choice poll the broadcast shows both choices', mineIdx(m.root.children[0]).join() === '0,2', mineIdx(m.root.children[0]));
  });
  await withDeadline('watch: slow mode', async () => {
    const w = watchWorld();
    w.api.setSelect(15);                         // channel_info / slowmode_changed confirm 15
    w.slow.value = '30';                         // the moderator picks 30
    w.api.setSlowmode('30');
    check('the change is sent', w.sent.length === 1 && w.sent[0].type === 'set_slowmode' && w.sent[0].seconds === 30, JSON.stringify(w.sent));
    // the server refuses: an error frame
    vm.runInContext('(function(data){ ' + watchErrorBranch() + ' })', w.sandbox)({ type: 'error', message: 'Not authorized' });
    check('a refused slow mode value returns the select to the last confirmed one', w.slow.value === '15', w.slow.value);
    w.api.setSlowmode('5'); w.slow.value = '5';
    w.api.setSelect(5);                          // confirmed this time
    vm.runInContext('(function(data){ ' + watchErrorBranch() + ' })', w.sandbox)({ type: 'error', message: 'Poll is closed' });
    check('an error that follows a confirmed change leaves the select alone', w.slow.value === '5', w.slow.value);
  });

  // ---- chat.html ------------------------------------------------------------------------------------------
  await withDeadline('chat: highlight kept', async () => {
    const card = { outerHTML: '' };
    const sandbox = {
      document: { querySelector: () => card },
      escapeHtml: (t) => String(t),
      currentUser: { id: 9, role: 'user' },
      HistoryView: { buffer: [] },
      ws: { readyState: 1, send() {} }, WebSocket: { OPEN: 1 },
      console,
    };
    card.closest = () => null;
    vm.createContext(sandbox);
    const code = [optLine(chatHtml, /const pollMine = [^\n]*;/, 'const pollMine = new Map();'), optLine(chatHtml, /const pollMulti = [^\n]*;/, 'const pollMulti = new Map();'),
      fn(chatHtml, 'bufferApplyPoll'), fn(chatHtml, 'renderPollCard'), fn(chatHtml, 'updatePollDisplay'), fn(chatHtml, 'votePoll'),
      'this.api = { render: renderPollCard, update: updatePollDisplay, vote: votePoll };'].join('\n');
    vm.runInContext(code, sandbox);
    const api = sandbox.api;
    const voted = (html) => (html.match(/class="poll-option voted /g) || []).length;
    const poll = (extra) => Object.assign({ id: 4, question: 'q', options: ['a', 'b', 'c'], votes: { 0: 1 }, allow_multiple: 0, is_closed: 0, user_id: 1, my_votes: [] }, extra || {});
    const first = api.render(poll({ my_votes: [1] }), 'x');
    check('a card rendered with my_votes shows the choice', voted(first) === 1 && /poll-option voted [^>]*onclick="votePoll\(4, 1\)"/.test(first));
    api.update(poll({ my_votes: [] }));
    check('a poll_updated frame without my_votes keeps the choice', voted(card.outerHTML) === 1 && /poll-option voted [^>]*onclick="votePoll\(4, 1\)"/.test(card.outerHTML), card.outerHTML.slice(0, 400));
    api.update(poll({ id: 5 }));
    check('another poll does not take the kept choice', voted(card.outerHTML) === 0);
    api.vote(4, 2);
    api.update(poll({ my_votes: [] }));
    check('after a vote in a single-choice poll the broadcast shows the new choice only', voted(card.outerHTML) === 1 && /poll-option voted [^>]*onclick="votePoll\(4, 2\)"/.test(card.outerHTML), card.outerHTML.slice(0, 400));
  });
  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness crashed', ok: false, detail: e && e.stack })); });

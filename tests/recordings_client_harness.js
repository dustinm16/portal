// Runs static/js/recordings-admin.js under Node against a small fake DOM, a fake fetch and a fake xterm.
// usage: node recordings_client_harness.js <recordings-admin.js>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const path = require('path');
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

// ---- fake DOM: elements are made on demand by id --------------------------------------------
class El {
  constructor(tag) { this.tag = tag; this.children = []; this.style = {}; this.listeners = {}; this.dataset = {}; this.value = ''; this.disabled = false; this._text = ''; this.attrs = {}; }
  appendChild(c) { this.children.push(c); c.parent = this; return c; }
  removeChild(c) { this.children = this.children.filter(x => x !== c); }
  addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  click() { this.clicked = true; }
  closest() { return this; }
  all() { return [this].concat(...this.children.map(c => c.all())); }
}
const els = {};
const docListeners = {};
const body = new El('body');
global.document = {
  readyState: 'complete', body, head: new El('head'),
  createElement: t => new El(t),
  getElementById: id => (els[id] = els[id] || new El('div')),
  addEventListener: (t, fn) => (docListeners[t] = docListeners[t] || []).push(fn),
};
const $ = id => document.getElementById(id);
$('rec-modal').style.display = 'none';
$('tab-btn-recordings').style.display = 'none';
$('rec-speed').value = '1';

// ---- fake xterm ------------------------------------------------------------------------------
const terms = [];
class FakeTerminal {
  constructor(opts) { this.opts = opts; this.cols = opts.cols; this.rows = opts.rows; this.written = []; this.resizes = []; this.disposed = false; terms.push(this); }
  open() {} reset() {}
  write(s) { this.written.push(s); }
  resize(c, r) { this.cols = c; this.rows = r; this.resizes.push([c, r]); }
  dispose() { this.disposed = true; }
}
global.Terminal = FakeTerminal;

// ---- fake timers: nothing runs by itself ----------------------------------------------------
let timers = [], timerId = 0;
global.setTimeout = (fn, ms) => { const id = ++timerId; timers.push({ id, fn, ms }); return id; };
global.clearTimeout = (id) => { timers = timers.filter(t => t.id !== id); };
function runTimers(max) { let n = 0; while (timers.length && n++ < (max || 1000)) { const t = timers.shift(); t.fn(); } }

// ---- fake portal ----------------------------------------------------------------------------
const toasts = [], fetches = [];
let castAnswers = {};            // id -> deferred {resolve}
let listAnswer = () => ({ recordings: [], total: 0 });
function deferred() { let resolve; const p = new Promise(r => { resolve = r; }); return { p, resolve }; }
const created = [];
global.URL = { createObjectURL: (b) => { created.push(b); return 'blob:fake/' + created.length; }, revokeObjectURL: () => {} };
const assigned = [];
global.window = global;
global.location = { assign: u => assigned.push(u) };
global.showTab = () => {};
let confirmAnswer = true;
global.confirm = () => confirmAnswer;
global.Portal = {
  toast: (m, k) => toasts.push([m, k]),
  fetch: async (url, opts) => {
    fetches.push({ url, method: (opts && opts.method) || 'GET' });
    if (/\/api\/recordings\?/.test(url)) {
      const data = listAnswer(url);
      return { ok: true, status: 200, json: async () => data };
    }
    const m = /\/api\/recordings\/(\d+)\/cast/.exec(url);
    if (m) { const d = castAnswers[m[1]]; return d.p; }
    const del = /\/api\/recordings\/(\d+)$/.exec(url);
    if (del && opts && opts.method === 'DELETE') return deleteAnswer;
    throw new Error('unexpected fetch ' + url);
  },
};
let deleteAnswer = null;
const cast = (header, events) => ({
  ok: true, status: 200,
  text: async () => JSON.stringify(header) + '\n' + events.map(e => JSON.stringify(e)).join('\n') + '\n',
  blob: async () => ({ size: 1, type: 'application/x-asciicast' }),
});
const flush = () => new Promise(r => setImmediate(r));
const bodyOf = () => $('rec-body');

require(path.resolve(process.argv[2]));
const RA = global.RecordingsAdmin;

(async () => {
  const row = (id, extra) => Object.assign({ id, user: 'bob', connection: 'box', type: 'ssh', started_at: '2026-11-21T10:00:00Z', ended_at: '2026-11-21T10:01:00Z', size: 100, live: false }, extra);
  const click = async (action, id) => {
    const b = { dataset: { action, id: String(id), label: 'bob / box' } };
    for (const fn of $('rec-body').listeners.click) await fn({ target: { closest: () => b } });
    await flush();
  };

  // ---- the list and the pages: the last row of the last page is deleted -------------------------
  listAnswer = (url) => /page=2/.test(url) ? { recordings: [], total: 25 } : { recordings: [row(1)], total: 25 };
  $('rec-next').listeners.click.forEach(fn => fn());   // page 2 (the button is not disabled by the fake)
  await flush(); await flush();
  const listUrls = fetches.filter(f => /\/api\/recordings\?.*page=/.test(f.url)).map(f => /page=(\d+)/.exec(f.url)[1]);
  check('an empty last page steps back to the page that has rows', listUrls.join(',') === '2,1', listUrls.join(','));
  check('... and shows its rows and page number', $('rec-page-info').textContent === 'Page 1 of 1' && $('rec-body').children.length === 1, $('rec-page-info').textContent);

  // ---- delete messages ---------------------------------------------------------------------------
  listAnswer = () => ({ recordings: [row(1)], total: 1 });
  deleteAnswer = { ok: true, status: 200, json: async () => ({ deleted: 1, file_removed: true }) };
  await click('delete', 1);
  check('a delete that removed the file says deleted', toasts.some(t => t[0] === 'Recording deleted' && t[1] === 'success'), JSON.stringify(toasts));
  deleteAnswer = { ok: true, status: 200, json: async () => ({ deleted: 2, file_removed: false }) };
  await click('delete', 2);
  check('a delete of an entry with no plain file name says no file was touched',
    toasts.some(t => t[0] === 'Entry removed, no file was touched' && t[1] === 'success'), JSON.stringify(toasts));
  deleteAnswer = { ok: false, status: 500, json: async () => ({ error: 'The file could not be removed; nothing was deleted' }) };
  await click('delete', 3);
  check('a refused delete is an error toast', toasts.some(t => /^Could not delete: The file could not be removed/.test(t[0]) && t[1] === 'error'));

  // ---- cancelling a load ---------------------------------------------------------------------------
  const startTerms = terms.length;
  castAnswers['10'] = deferred();
  await click('play', 10);
  check('Play opens the modal and says Loading', $('rec-modal').style.display === '' && $('rec-play-status').textContent === 'Loading');
  $('rec-modal-close').listeners.click.forEach(fn => fn());
  castAnswers['10'].resolve(cast({ version: 2, width: 80, height: 24 }, [[0.1, 'o', 'late']]));
  await flush(); await flush();
  check('closing the modal while the cast loads: no terminal is made and nothing plays',
    terms.length === startTerms && $('rec-modal').style.display === 'none' && timers.length === 0, `${terms.length - startTerms} ${timers.length}`);
  check('... and the status line is not rewritten', $('rec-play-status').textContent === 'Loading');

  castAnswers['11'] = deferred(); castAnswers['12'] = deferred();
  await click('play', 11);
  await click('play', 12);
  check('the title names the latest row', /^Recording 12 /.test($('rec-modal-title').textContent), $('rec-modal-title').textContent);
  castAnswers['12'].resolve(cast({ version: 2, width: 90, height: 30 }, [[0.1, 'o', 'twelve']]));
  await flush(); await flush();
  castAnswers['11'].resolve(cast({ version: 2, width: 100, height: 40 }, [[0.1, 'o', 'eleven']]));
  await flush(); await flush();
  const live = terms.filter(t => !t.disposed);
  check('pressing Play on another row before the first loaded: only the later one plays, whatever order they arrive in',
    live.length === 1 && live[0].written.join('') === 'twelve' && /^Recording 12 /.test($('rec-modal-title').textContent),
    JSON.stringify(live.map(t => t.written)));
  $('rec-modal-close').listeners.click.forEach(fn => fn());
  check('closing the modal stops the playback and disposes the terminal', terms.filter(t => !t.disposed).length === 0 && timers.length === 0);
  // the earlier one arriving first
  castAnswers['13'] = deferred(); castAnswers['14'] = deferred();
  await click('play', 13); await click('play', 14);
  castAnswers['13'].resolve(cast({ version: 2, width: 80, height: 24 }, [[0.1, 'o', 'thirteen']]));
  await flush(); await flush();
  check('a stale load that arrives first draws nothing', terms.filter(t => !t.disposed).length === 0);
  castAnswers['14'].resolve(cast({ version: 2, width: 80, height: 24 }, [[0.1, 'o', 'fourteen']]));
  await flush(); await flush();
  check('... and the current load then plays', terms.filter(t => !t.disposed).length === 1 && terms.filter(t => !t.disposed)[0].written.join('') === 'fourteen');
  $('rec-modal-close').listeners.click.forEach(fn => fn());

  // ---- size clamps -----------------------------------------------------------------------------------
  const play = async (id, header, events) => {
    castAnswers[id] = deferred(); await click('play', id);
    castAnswers[id].resolve(cast(header, events)); await flush(); await flush();
    return terms.filter(t => !t.disposed).pop();
  };
  let t = await play('20', { version: 2, width: 100000, height: 100000 }, [[0.1, 'o', 'x']]);
  check('a header size far above the limit is clamped to 500 x 200', t && t.opts.cols === 500 && t.opts.rows === 200, t && `${t.opts.cols}x${t.opts.rows}`);
  $('rec-modal-close').listeners.click.forEach(fn => fn());
  t = await play('21', { version: 2, width: 'wide', height: -4 }, [[0.1, 'o', 'x']]);
  check('a header size that is not a positive number falls back to 80 x 24', t && t.opts.cols === 80 && t.opts.rows === 24, t && `${t.opts.cols}x${t.opts.rows}`);
  $('rec-modal-close').listeners.click.forEach(fn => fn());
  t = await play('22', { version: 2, width: 120, height: 50 }, [[0.1, 'o', 'x']]);
  check('a normal header size is kept', t.opts.cols === 120 && t.opts.rows === 50);
  $('rec-modal-close').listeners.click.forEach(fn => fn());
  t = await play('23', { version: 2, width: 80, height: 24 }, [[0.1, 'r', '9999x9999'], [0.2, 'r', '132x43'], [0.3, 'r', '0x0'], [0.4, 'o', 'y']]);
  runTimers();
  check('resize events are clamped to 500 x 200 as well', t.resizes.some(r => r[0] === 500 && r[1] === 200) && !t.resizes.some(r => r[0] > 500 || r[1] > 200), JSON.stringify(t.resizes));
  check('a normal resize event is applied as it is', t.resizes.some(r => r[0] === 132 && r[1] === 43), JSON.stringify(t.resizes));
  check('a resize event of 0 columns by 0 rows never reaches the terminal as zero', !t.resizes.some(r => r[0] < 1 || r[1] < 1), JSON.stringify(t.resizes));

  // ---- Escape -------------------------------------------------------------------------------------------
  const esc = (k) => (docListeners.keydown || []).forEach(fn => fn({ key: k }));
  esc('Enter');
  check('another key leaves the modal open', $('rec-modal').style.display === '');
  esc('Escape');
  check('Escape closes the modal and disposes the terminal', $('rec-modal').style.display === 'none' && terms.filter(x => !x.disposed).length === 0);
  const before = timers.length;
  esc('Escape');
  check('Escape with the modal already closed does nothing', $('rec-modal').style.display === 'none' && timers.length === before);

  // ---- download ---------------------------------------------------------------------------------------------
  const fetchesBefore = fetches.length;
  castAnswers['30'] = deferred();
  const dl = click('download', 30);
  castAnswers['30'].resolve(cast({ version: 2, width: 80, height: 24 }, []));
  await dl; await flush();
  const dlFetch = fetches.slice(fetchesBefore).find(f => /\/30\/cast/.test(f.url));
  check('Download fetches the cast with ?download=1 (so the audit says download)', dlFetch && /\/api\/recordings\/30\/cast\?download=1$/.test(dlFetch.url), JSON.stringify(dlFetch));
  const anchors = body.children.concat(created.length ? [] : []);
  check('Download saves a blob through an object URL and a named link', created.length === 1 && assigned.length === 0, `${created.length} ${assigned.length}`);
  check('the page is never navigated to the raw file', assigned.length === 0);
  castAnswers['31'] = { p: Promise.resolve({ ok: false, status: 404, text: async () => '', blob: async () => ({}) }) };
  const toastsBefore = toasts.length;
  await click('download', 31);
  check('a failed download is a toast and nothing is saved', toasts.length === toastsBefore + 1 && toasts[toasts.length - 1][1] === 'error'
    && /Could not download: The file is gone/.test(toasts[toasts.length - 1][0]) && created.length === 1, JSON.stringify(toasts.slice(-1)));
  check('the download link is removed from the page again', body.children.length === 0);

  // ---- each of the three stale checks in play() on its own ---------------------------------------------------
  // play() awaits loadXterm(), then the fetch, then the text; after each await it drops out when the load
  // has become stale. Every case here goes stale at exactly one of those points and asserts that nothing
  // later happens: the case for an await also fails when only its own check is deleted (the next check
  // would otherwise hide the missing one, so each case looks at what the missing check would let through).
  const closeModal = () => $('rec-modal-close').listeners.click.forEach(fn => fn());
  const liveTerms = () => terms.filter(x => !x.disposed).length;
  closeModal();
  const RealTerminal = global.Terminal;

  // await 1: xterm.js is still loading when the modal is closed
  global.Terminal = undefined;
  castAnswers['40'] = deferred();
  const headBefore = document.head.children.length;
  await click('play', 40);
  const scriptEl = document.head.children.slice(headBefore).find(c => c.tag === 'script');
  check('stale-after-xterm: the player waits for xterm.js to load', !!scriptEl && typeof scriptEl.onload === 'function' && !fetches.some(f => /\/40\/cast/.test(f.url)));
  closeModal();
  global.Terminal = RealTerminal;
  if (scriptEl && scriptEl.onload) scriptEl.onload();
  castAnswers['40'].resolve(cast({ version: 2, width: 80, height: 24 }, [[0.1, 'o', 'forty']]));
  await flush(); await flush();
  check('stale-after-xterm: closing the modal while xterm.js loads: the cast is not even requested',
    !fetches.some(f => /\/40\/cast/.test(f.url)), JSON.stringify(fetches.filter(f => /\/40\/cast/.test(f.url))));
  check('stale-after-xterm: ... and no player is created', liveTerms() === 0, String(liveTerms()));

  // await 2: the answer arrives after the modal was closed; its body must not be read
  let textCalls = 0;
  castAnswers['41'] = deferred();
  await click('play', 41);
  closeModal();
  castAnswers['41'].resolve({ ok: true, status: 200, text: async () => { textCalls++; return '{"version":2,"width":80,"height":24}\n[0.1,"o","x"]\n'; } });
  await flush(); await flush();
  check('stale-after-fetch: an answer that arrives after the modal was closed is not read', textCalls === 0, String(textCalls));
  check('stale-after-fetch: ... and no player is created', liveTerms() === 0, String(liveTerms()));

  // await 3: the body is still being read when the modal is closed
  const textGate = deferred();
  const timersBefore = timers.length;
  castAnswers['42'] = deferred();
  await click('play', 42);
  castAnswers['42'].resolve({ ok: true, status: 200, text: () => textGate.p });
  await flush();
  closeModal();
  textGate.resolve('{"version":2,"width":80,"height":24}\n[0.1,"o","x"]\n');
  await flush(); await flush();
  check('stale-after-text: a body that is read after the modal was closed creates no player', liveTerms() === 0 && timers.length === timersBefore, `${liveTerms()} ${timers.length} ${timersBefore}`);
  check('stale-after-text: ... and the status line is not rewritten', $('rec-play-status').textContent === 'Loading', $('rec-play-status').textContent);
  // the same, but another row was started in between
  const gate2 = deferred();
  castAnswers['43'] = deferred(); castAnswers['44'] = deferred();
  await click('play', 43);
  castAnswers['43'].resolve({ ok: true, status: 200, text: () => gate2.p });
  await flush();
  await click('play', 44);
  gate2.resolve('{"version":2,"width":80,"height":24}\n[0.1,"o","fortythree"]\n');
  await flush(); await flush();
  check('stale-after-text: a body read after Play on another row creates no player', liveTerms() === 0, String(liveTerms()));
  castAnswers['44'].resolve(cast({ version: 2, width: 80, height: 24 }, [[0.1, 'o', 'fortyfour']]));
  await flush(); await flush();
  check('stale-after-text: ... and the later row plays', liveTerms() === 1 && terms.filter(x => !x.disposed)[0].written.join('') === 'fortyfour');
  closeModal();

  // ---- parseCast is still exported ---------------------------------------------------------------------------------
  check('parseCast still reads a cast', RA.parseCast('{"version":2,"width":80,"height":24}\n[0.5,"o","a"]\n').events.length === 1);

  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness crashed', ok: false, detail: String(e && e.stack || e) })); });

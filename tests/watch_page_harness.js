// Runs functions of static/watch.html under Node against a small fake page: the poll that follows a stream
// while the page is open (offline then live again, a ban, a removed stream). No browser: the real player, real
// timers and the look of the page are not covered.
// Used by tests/test_watch_page.py.
//
// usage: node watch_page_harness.js <path to watch.html>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(process.argv[2], 'utf8');
// One function (plain or async) by name, cut at its closing brace.
function fn(name) {
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
function constLine(name) {
  const m = html.match(new RegExp('const ' + name + ' = [^\\n]*;'));
  if (!m) throw new Error('const not found: ' + name);
  return m[0];
}
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }
async function withDeadline(name, f, ms) {
  let timer;
  const late = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('no answer within ' + (ms || 5000) + ' ms')), ms || 5000); });
  try { await Promise.race([f(), late]); } catch (e) { check(name + ' (did not finish)', false, e && e.message); } finally { clearTimeout(timer); }
}

function world() {
  const els = {};
  const log = { setup: 0, ensure: 0, beatStops: 0, offline: 0, encoding: 0, loadErrors: [], destroyed: 0, cleared: [], href: '' };
  const mk = (id) => { const e = { id, style: {}, textContent: '', _inner: '' }; els[id] = e; return e; };
  ['viewer-title', 'live-indicator', 'viewer-count', 'viewer-count-value'].forEach(mk);
  const container = mk('video-container');
  Object.defineProperty(container, 'innerHTML', { get() { return container._inner; }, set(v) { container._inner = v; if (String(v).includes('id="stream-video"')) mk('stream-video'); else delete els['stream-video']; } });
  mk('stream-video');
  const state = { answer: null };
  const sandbox = {
    document: { getElementById: (id) => els[id] || null },
    window: { location: { set href(v) { log.href = v; }, get href() { return log.href; } } },
    clearInterval: (t) => log.cleared.push(t),
    console: { error() {}, log() {} },
    streamId: 5, chatOnly: false, streamData: null, hlsPlayer: null, refreshInterval: 77,
    fetch: () => Promise.resolve(state.answer),
    showStreamInfo() {},
    showOfflineMessage() { log.offline++; container.innerHTML = '<div class="stream-offline"></div>'; },
    showEncodingMessage() { log.encoding++; container.innerHTML = '<div class="stream-offline"></div>'; },
    setupVideo() { log.setup++; },
    stopViewerBeat() { log.beatStops++; },
  };
  vm.createContext(sandbox);
  // A page without a helper still loads, so the checks fail on behaviour instead of on a missing name
  const opt = (f, fallback) => { try { return f(); } catch (e) { return fallback; } };
  vm.runInContext([opt(() => constLine('BANNED_STREAM_TEXT'), "const BANNED_STREAM_TEXT = '';"), 'let playerStarted = false;',
    opt(() => fn('ensureVideoElement'), 'function ensureVideoElement() {}'), opt(() => fn('stopWatching'), 'function stopWatching() {}'),
    fn('showLoadError'), fn('refreshStreamInfo'),
    'this.api = { refresh: refreshStreamInfo, ensure: ensureVideoElement, started: () => playerStarted, setStarted: (v) => { playerStarted = v; } };'].join('\n'), sandbox);
  // keep the log of load errors: showLoadError writes the title and, in the pop-out, a system line
  sandbox.appendSystemMessage = (t) => log.loadErrors.push(t);
  sandbox.destroyable = { destroy() { log.destroyed++; } };
  return { sandbox, els, log, state, api: sandbox.api };
}
function reply(status, body) { return { status, ok: status >= 200 && status < 300, json: async () => body }; }
function live(n) { return reply(200, { stream: { name: 'n', game: '', is_live: n } }); }

(async () => {
  await withDeadline('offline then live', async () => {
    const w = world();
    w.api.setStarted(true);                       // the page loaded while the stream was live
    w.state.answer = live(0); await w.api.refresh();
    check('going offline shows the offline page, stops the heartbeat and lets the player restart', w.log.offline === 1 && !w.api.started() && !w.els['stream-video']);
    w.state.answer = live(1); await w.api.refresh();
    check('offline then live puts the video element back and starts the player once', w.log.setup === 1 && w.api.started() && !!w.els['stream-video'], JSON.stringify(w.log));
    check('the heartbeat is reset before the new player starts (so it listens to the new element)', w.log.beatStops >= 2, w.log.beatStops);
    w.state.answer = live(1); await w.api.refresh(); await w.api.refresh();
    check('a stream that stays live does not start the player again', w.log.setup === 1, w.log.setup);
    check('the live indicator and the count are shown', w.els['live-indicator'].style.display === 'flex' && w.els['viewer-count'].style.display === 'flex');
  });
  await withDeadline('encoding then live', async () => {
    const w = world();
    w.api.setStarted(true);
    w.state.answer = live(2); await w.api.refresh();
    w.state.answer = live(1); await w.api.refresh();
    check('encoding then live starts the player once', w.log.encoding === 1 && w.log.setup === 1 && !!w.els['stream-video'], JSON.stringify(w.log));
  });
  await withDeadline('first load offline', async () => {
    const w = world();
    w.state.answer = live(0); await w.api.refresh();
    w.state.answer = live(1); await w.api.refresh();
    check('a page opened on an offline stream starts the player when it goes live', w.log.setup === 1 && !!w.els['stream-video']);
  });
  await withDeadline('ban', async () => {
    const w = world();
    w.sandbox.hlsPlayer = w.sandbox.destroyable;
    w.state.answer = reply(403, { banned: true, error: 'x' }); await w.api.refresh();
    check('a 403 banned answer shows the banned text and stops the polling and the player',
      w.els['viewer-title'].textContent === 'You are banned from this stream by its owner. The ban applies to watching while signed in.'
      && w.log.cleared.includes(77) && w.sandbox.refreshInterval === null && w.log.destroyed === 1 && w.sandbox.hlsPlayer === null && w.log.beatStops === 1, JSON.stringify(w.log) + w.els['viewer-title'].textContent);
  });
  await withDeadline('404', async () => {
    const w = world();
    w.state.answer = reply(404, { error: 'nope' }); await w.api.refresh();
    check('a 404 answer shows Stream not found and stops the polling', w.els['viewer-title'].textContent === 'Stream not found' && w.log.cleared.includes(77));
  });
  await withDeadline('other refusals', async () => {
    const w = world();
    w.state.answer = reply(403, { error: 'forbidden' }); await w.api.refresh();
    check('a 403 that is not a ban changes nothing', w.els['viewer-title'].textContent === '' && w.log.cleared.length === 0);
    w.state.answer = reply(500, {}); await w.api.refresh();
    check('a server error changes nothing and keeps polling', w.els['viewer-title'].textContent === '' && w.log.cleared.length === 0);
    w.state.answer = reply(401, {}); await w.api.refresh();
    check('a 401 still goes to the login page', w.log.href === '/login' && w.log.cleared.includes(77));
  });
  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness crashed', ok: false, detail: e && e.stack })); });

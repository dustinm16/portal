// Runs static/js/rbrowser.js (the Web Browser page) under Node against fakes: a fake document built from the ids of
// static/rbrowser.html, a fake fetch, WebSocket, noVNC RFB, storage and clock. No browser, no network, no real timers.
// What it cannot show: layout, a real noVNC, a real phone keyboard, a real clipboard.
// Used by tests/test_rbrowser_page.py.
//
// usage: node rbrowser_page_harness.js <rbrowser.js> <rbrowser.html> [<rbrowser-admin.js> <dashboard.js>]
// With the last two arguments it also runs the admin card (static/js/rbrowser-admin.js) against a sample answer and
// the dashboard card (loadRbrowserCard in static/js/dashboard.js) against status answers.
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const source = fs.readFileSync(process.argv[2], 'utf8');
const html = fs.readFileSync(process.argv[3], 'utf8');
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

// The module's one import is replaced by a binding from the sandbox; nothing else needs changing.
const importLine = /^import RFB from '\/static\/vendor\/novnc\/core\/rfb\.js\?v=1\.4\.0';\n/;
if (!importLine.test(source)) { console.log('RESULT ' + JSON.stringify({ name: 'the module starts with the noVNC import line', ok: false, detail: source.slice(0, 120) })); process.exit(0); }
const code = source.replace(importLine, '');

const sandbox = { console: { log() {}, error() {}, warn() {} }, Array, Object, Math, Date, JSON, Number, String, Promise, isFinite, Error };
vm.createContext(sandbox);
vm.runInContext(code, sandbox, { filename: 'rbrowser.js' });
const P = sandbox.PortalRbrowser;

// ---- fake DOM from the page's markup ----
const tagRx = /<([a-zA-Z0-9]+)\b[^>]*?\bid="([^"]+)"[^>]*>/g;
const PAGE = [];
let m;
while ((m = tagRx.exec(html))) PAGE.push({ tag: m[1].toUpperCase(), id: m[2], hidden: /\shidden(\s|>|=|\/)/.test(m[0]) });

// The ancestors of every id in the page (read from the markup), so a check can say whether an element is on the
// screen at all (hidden itself, or inside something hidden), not only whether its own flag is clear.
const PARENT = {};
{
  const stack = [];   // the nearest element with an id, for every open tag
  const VOID = /^(meta|link|br|hr|img|input)$/i;
  const rx = /<(\/?)([a-zA-Z0-9]+)\b([^>]*?)>/g;
  let t;
  while ((t = rx.exec(html))) {
    if (t[1]) { stack.pop(); continue; }
    if (VOID.test(t[2]) || /\/$/.test(t[3])) continue;
    const top = stack.length ? stack[stack.length - 1] : null;
    const id = /\bid="([^"]+)"/.exec(t[3]);
    if (id) PARENT[id[1]] = top;
    stack.push(id ? id[1] : top);
  }
}

class El {
  constructor(tag, id, hidden) {
    this.tagName = tag; this.id = id; this.hidden = !!hidden; this.disabled = false; this.children = []; this.listeners = {};
    this._text = ''; this.value = ''; this.className = ''; this.title = ''; this.attrs = {}; this.parentNode = null;
    this.clientWidth = 0; this.clientHeight = 0; this.focused = false; this.focusCalls = 0;
  }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set innerHTML(v) { innerHtmlWrites.push(this.id); throw new Error('innerHTML must never be assigned'); }
  get innerHTML() { return ''; }
  appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(t, f, capture) { (this.listeners[t] = this.listeners[t] || []).push({ f, capture: !!capture }); }
  focus() { this.focusCalls++; this.focused = true; this.fire('focus', {}); }
  blur() { this.focused = false; this.fire('blur', {}); }
  fire(t, ev) { ev = ev || {}; (this.listeners[t] || []).slice().forEach(l => l.f(ev)); }
  async click(ev) { this.fire('click', Object.assign({ detail: 1 }, ev || {})); await flush(); }
}
const innerHtmlWrites = [];

async function flush() { for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r)); }
function json(status, body) { return { status, json: async () => body === undefined ? {} : body }; }

function ev(props) {
  const e = Object.assign({ stopped: false, defaultPrevented: false }, props || {});
  e.stopPropagation = () => { e.stopped = true; };
  e.preventDefault = () => { e.defaultPrevented = true; };
  return e;
}

class FakeWS {
  constructor(url) { this.url = url; this.sent = []; this.closed = false; this.listeners = {}; world_.sockets.push(this); }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  send(d) { this.sent.push(d); }
  close() { this.closed = true; }
  fireClose(code, reason) { (this.listeners.close || []).slice().forEach(f => f({ code, reason })); }
}
class FakeRFB {
  constructor(target, channel, opts) {
    this.target = target; this.channel = channel; this.opts = opts; this.listeners = {}; this.keys = []; this.pasted = [];
    this.disconnected = false; this.focused = 0; world_.rfbs.push(this);
  }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  emit(t, detail) { (this.listeners[t] || []).slice().forEach(f => f({ detail })); }
  sendKey(sym, code, down) { this.keys.push([sym, code, down]); }
  clipboardPasteFrom(t) { this.pasted.push(t); }
  disconnect() { this.disconnected = true; }
  focus() { this.focused++; }
}
let world_ = null;

function world(opts) {
  opts = opts || {};
  const w = { sockets: [], rfbs: [], calls: [], timers: [], clock: 1700000000000, seq: 0, assigned: [], docListeners: {}, store: opts.store || new Map(), clipWrites: [] };
  world_ = w;
  const els = {};
  for (const p of PAGE) els[p.id] = new El(p.tag, p.id, p.hidden);
  els['rb-stage'].clientWidth = opts.stageW || 1000;
  els['rb-stage'].clientHeight = opts.stageH || 700;
  const canvas = new El('CANVAS', 'canvas', false);
  els['rb-screen'].appendChild(canvas);
  w.canvas = canvas;
  w.novncKeys = 0;
  canvas.addEventListener('keydown', () => { w.novncKeys++; });
  if (opts.beforeInput !== false) els['rb-kbd'].onbeforeinput = null;   // property present = beforeinput supported
  w.els = els;

  const routes = {};
  w.route = (key, resp) => { routes[key] = Array.isArray(resp) ? resp.slice() : [resp]; };
  const fetch = async (url, init) => {
    const method = (init && init.method) || 'GET';
    const body = init && init.body ? JSON.parse(init.body) : undefined;
    w.calls.push({ method, url, body });
    const r = routes[method + ' ' + url];
    if (!r) return json(404, {});
    const x = r.length > 1 ? r.shift() : r[0];
    if (x === 'throw') throw new Error('network');
    return x;
  };
  const doc = {
    getElementById: id => els[id] || null,
    createElement: t => new El(t.toUpperCase(), '', false),
    addEventListener(t, f, capture) { (w.docListeners[t] = w.docListeners[t] || []).push({ f, capture: !!capture }); },
    documentElement: { requestFullscreen() { w.fullscreen = true; return Promise.resolve(); } },
    fullscreenEnabled: opts.fullscreen !== false,
  };
  const win = { innerWidth: 1000, innerHeight: 700, listeners: {}, addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); } };
  w.win = win;
  const storage = {
    getItem: k => { if (opts.storageThrows) throw new Error('denied'); return w.store.has(k) ? w.store.get(k) : null; },
    setItem: (k, v) => { if (opts.storageThrows) throw new Error('denied'); w.store.set(k, String(v)); },
    removeItem: k => { if (opts.storageThrows) throw new Error('denied'); w.store.delete(k); },
  };
  const env = {
    doc, win, fetch, WebSocket: FakeWS, RFB: FakeRFB, storage,
    setTimeout: (f, ms) => { const id = ++w.seq; w.timers.push({ id, at: w.clock + ms, ms, f }); return id; },
    clearTimeout: id => { w.timers = w.timers.filter(t => t.id !== id); },
    now: () => w.clock,
    clipboard: { writeText: async t => { w.clipWrites.push(t); } },
    navigator: {},
    location: { assign: u => w.assigned.push(u) },
    wsUrl: p => 'wss://portal.example' + p,
  };
  w.ctl = P.create(env);
  w.advance = async ms => {
    const target = w.clock + ms;
    for (;;) {
      await flush();
      const due = w.timers.filter(t => t.at <= target).sort((a, b) => a.at - b.at || a.id - b.id)[0];
      if (!due) break;
      w.timers = w.timers.filter(t => t !== due);
      w.clock = Math.max(w.clock, due.at);
      due.f();
    }
    await flush();
    w.clock = target;
  };
  w.pending = () => w.timers.map(t => t.ms);
  w.key = (target, props) => {
    const e = ev(Object.assign({ target }, props));
    for (const l of (w.docListeners.keydown || []).filter(l => l.capture)) l.f(e);
    if (!e.stopped) target.fire('keydown', e);
    return e;
  };
  w.paste = (target, text) => {
    const e = ev({ target, clipboardData: { getData: () => text } });
    for (const l of (w.docListeners.paste || []).filter(l => !l.capture)) l.f(e);
    return e;
  };
  return w;
}

const status = (over) => json(200, Object.assign({ available: true, enabled: true, allowed: true, busy: false, checking: false, clipboard: 'both', boot_id: 'boot-A' }, over));
function sessionInfo(w, over) {
  const now = w.clock / 1000;
  return Object.assign({ sid: 'abc', ws: '/ws/rbrowser/abc', width: 992, height: 688, idle_deadline: now + 900, max_deadline: now + 14400, clipboard: 'both', net_warning: false }, over);
}
function happy(w, over, boot) {
  w.route('GET /api/rbrowser/status', status(boot ? { boot_id: boot } : {}));
  const info = sessionInfo(w, over);
  w.route('GET /api/rbrowser/session', [json(404, {}), json(200, info)]);
  w.route('POST /api/rbrowser/session', json(201, info));
  w.route('POST /api/rbrowser/session/resize', json(200, { ok: true }));
  w.route('DELETE /api/rbrowser/session', json(204));
  return info;
}
async function connect(w, over, boot) {
  const info = happy(w, over, boot);
  await w.ctl.start();
  w.rfbs[w.rfbs.length - 1].emit('connect');
  await flush();
  return info;
}
const text = (w, id) => w.els[id].textContent;
const vis = (w, id) => !w.els[id].hidden;
// on the screen: neither the element nor any element around it is hidden
const onScreen = (w, id) => { for (let e = id; e; e = PARENT[e]) if (w.els[e].hidden) return false; return true; };
async function withDeadline(name, f, ms) {
  let timer;
  const late = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('no answer within ' + (ms || 8000) + ' ms')), ms || 8000); });
  try { await Promise.race([f(), late]); } catch (e) { check(name + ' (did not finish)', false, e && e.stack); } finally { clearTimeout(timer); }
}
const sent = (rfb) => rfb.keys.filter(k => k[2] === undefined).map(k => k[0]);
const hex = (a) => a.map(x => x.toString(16)).join(',');

(async () => {
  // ---- pure helpers ----
  await withDeadline('helpers', async () => {
    const c = P.clampSize;
    check('clamp: a phone-sized canvas is raised to the minimum width and height', JSON.stringify(c(390, 300)) === JSON.stringify({ width: P.MIN_W, height: 480 }), JSON.stringify(c(390, 300)));
    check('clamp: a large screen is cut at 1920 x 1200', JSON.stringify(c(3000, 2000)) === '{"width":1920,"height":1200}', JSON.stringify(c(3000, 2000)));
    check('clamp: sizes are cut down to a multiple of 16', JSON.stringify(c(1000, 700)) === '{"width":992,"height":688}', JSON.stringify(c(1000, 700)));
    check('clamp: not a number gives the minimum', JSON.stringify(c('x', undefined)) === JSON.stringify({ width: P.MIN_W, height: 480 }));
    const k = P.keysymsForText;
    check('keysym: ASCII is its own code', hex(k('Az 9~').keys) === '41,7a,20,39,7e', hex(k('Az 9~').keys));
    check('keysym: Latin-1 (e-acute, sharp s, nbsp, y-diaeresis) is its own code', hex(k('éß ÿ').keys) === 'e9,df,a0,ff');
    check('keysym: above Latin-1 is 0x01000000 + the code point (euro, curly quote, Cyrillic)', hex(k('\u20ac\u201c\u0434').keys) === '10020ac,100201c,1000434', hex(k('\u20ac\u201c\u0434').keys));
    check('keysym: an astral character (emoji) is one key, not two surrogates', hex(k('\u{1F600}').keys) === '101f600', hex(k('\u{1F600}').keys));
    check('keysym: newline is Return, CRLF and CR are one Return each', hex(k('a\nb\r\nc\rd').keys) === '61,ff0d,62,ff0d,63,ff0d,64', hex(k('a\nb\r\nc\rd').keys));
    check('keysym: tab is Tab', hex(k('\t').keys) === 'ff09');
    const sk = k('a\u0001\u007f\u0085b');
    check('keysym: control characters are skipped and counted', hex(sk.keys) === '61,62' && sk.skipped === 3, JSON.stringify(sk));
    check('keysym: a lone surrogate is skipped', k('\ud800').keys.length === 0 && k('\ud800').skipped === 1);
    check('clipboard setting: both, in (and the server\'s to_browser) and off; anything else is off', P.normaliseClip('both') === 'both' && P.normaliseClip('in') === 'in' && P.normaliseClip('to_browser') === 'in' && P.normaliseClip('off') === 'off' && P.normaliseClip('x') === 'off' && P.normaliseClip(undefined) === 'off' && P.normaliseClip('BOTH') === 'off');
    check('deadline: epoch seconds, epoch milliseconds, ISO text, relative seconds, junk',
      P.parseDeadline(1700000900, 0) === 1700000900000 && P.parseDeadline(1700000900000, 0) === 1700000900000
      && P.parseDeadline('2023-11-14T22:28:20Z', 0) === Date.parse('2023-11-14T22:28:20Z') && P.parseDeadline(300, 5000) === 305000
      && P.parseDeadline(null, 0) === null && P.parseDeadline({}, 0) === null);
    check('end reasons: every reason of the design has its own sentence, an unknown one gets the fallback and is not echoed',
      ['closed', 'closed_in_browser', 'idle', 'detached', 'max_lifetime', 'traffic_limit', 'replaced', 'signed_out', 'admin_end', 'crash', 'portal_stop', 'start_failed', 'settings_changed', 'slow', 'protocol']
        .every(r => P.reasonText(r) && P.reasonText(r) !== P.reasonText('nonsense')) && P.reasonText('<b>x</b>') === 'The session ended.' && P.reasonText('toString') === 'The session ended.');
    check('constants are exposed for the later measurement', P.MIN_W === 560 && P.TYPE_CHUNK === 40 && P.TYPE_INTERVAL_MS === 30 && P.TYPE_MAX_CHARS === 5000 && P.QUALITY_LEVELS.length === 3 && P.DEFAULT_QUALITY === 'balanced');
  });

  // ---- start-up flow ----
  await withDeadline('start-up', async () => {
    const w = world();
    const info = happy(w);
    const p = w.ctl.start();
    check('the first view is a neutral "Loading", not the sandbox check', w.ctl.state === 'loading' && text(w, 'rb-overlay-title') === 'Loading');
    await p;
    check('order: status, then the session lookup, then create',
      w.calls.map(c => c.method + ' ' + c.url).join('|') === 'GET /api/rbrowser/status|GET /api/rbrowser/session|POST /api/rbrowser/session', JSON.stringify(w.calls));
    check('create sends the stage size, clamped and in multiples of 16', JSON.stringify(w.calls[2].body) === '{"width":992,"height":688}', JSON.stringify(w.calls[2].body));
    check('the socket goes to the path the API named', w.sockets.length === 1 && w.sockets[0].url === 'wss://portal.example/ws/rbrowser/abc', w.sockets.map(s => s.url).join());
    check('noVNC gets the page-owned socket, an empty password, scaling on and no session resizing',
      w.rfbs[0].channel === w.sockets[0] && w.rfbs[0].opts.credentials.password === '' && w.rfbs[0].scaleViewport === true && w.rfbs[0].resizeSession === false);
    check('while connecting the overlay says so', w.ctl.state === 'connecting' && vis(w, 'rb-overlay'));
    w.rfbs[0].emit('connect');
    check('connected: the overlay is gone, the status says Connected, the toolbar controls appear',
      w.ctl.state === 'connected' && !vis(w, 'rb-overlay') && text(w, 'rb-status-text') === 'Connected' && w.els['rb-status'].className === 'connection-status connected'
      && vis(w, 'rb-keyboard') && vis(w, 'rb-text-toggle') && vis(w, 'rb-quality-wrap') && vis(w, 'rb-fit') && vis(w, 'rb-fullscreen') && vis(w, 'rb-end'));
    check('the default quality pair is applied', w.rfbs[0].qualityLevel === 6 && w.rfbs[0].compressionLevel === 2, w.rfbs[0].qualityLevel);

    const w2 = world();
    w2.route('GET /api/rbrowser/status', status());
    w2.route('GET /api/rbrowser/session', json(200, sessionInfo(w2)));
    await w2.ctl.start();
    check('an existing session is attached again, nothing is created', w2.sockets.length === 1 && !w2.calls.some(c => c.method === 'POST'));

    const w3 = world();
    w3.route('GET /api/rbrowser/status', status());
    w3.route('GET /api/rbrowser/session', json(200, sessionInfo(w3, { ws: 'wss://evil.example/x' })));
    await w3.ctl.start();
    check('a socket path outside /ws/rbrowser/ is refused', w3.sockets.length === 0 && w3.ctl.state === 'error');

    for (const [name, resp, want] of [
      ['not available', status({ available: false, reason: 'Chromium is missing' }), 'not_available'],
      ['switched off', status({ enabled: false }), 'not_available'],
      ['not allowed', status({ allowed: false }), 'not_allowed'],
    ]) {
      const x = world();
      x.route('GET /api/rbrowser/status', resp);
      await x.ctl.start();
      check('status ' + name + ' stops there: ' + want + ', no session call, no socket', x.ctl.state === want && x.calls.length === 1 && x.sockets.length === 0, x.ctl.state);
    }
    const xa = world();
    xa.route('GET /api/rbrowser/status', status({ available: false, reason: '<b>Chromium</b> missing' }));
    await xa.ctl.start();
    check('an admin reason is shown as text', text(xa, 'rb-overlay-note') === '<b>Chromium</b> missing' && vis(xa, 'rb-overlay-note') && innerHtmlWrites.length === 0);

    const x401 = world();
    x401.route('GET /api/rbrowser/status', json(401, {}));
    await x401.ctl.start();
    check('a 401 goes to the sign-in page', x401.assigned.join() === '/login');
    const xe = world();
    xe.route('GET /api/rbrowser/status', 'throw');
    await xe.ctl.start();
    check('a network failure shows an error with a retry button', xe.ctl.state === 'error' && text(xe, 'rb-action') === 'Try again');

    const xc = world();
    xc.route('GET /api/rbrowser/status', [status({ checking: true }), status()]);
    xc.route('GET /api/rbrowser/session', [json(404, {})]);
    xc.route('POST /api/rbrowser/session', json(201, sessionInfo(xc)));
    await xc.ctl.start();
    check('status checking: "Checking the browser sandbox", retried in 10 s', xc.ctl.state === 'checking' && xc.pending().join() === '10000', xc.pending().join());
    await xc.advance(10000);
    check('... and then it carries on to a session', xc.sockets.length === 1);
  });

  // ---- create refusals, takeover ----
  await withDeadline('create refusals', async () => {
    const mk = () => { const w = world(); w.route('GET /api/rbrowser/status', status()); w.route('GET /api/rbrowser/session', json(404, {})); return w; };
    let w = mk();
    w.route('POST /api/rbrowser/session', json(409, { busy: true, free_in_minutes: 10 }));
    await w.ctl.start();
    check('busy: "a seat should be free in about N minutes", a Try again button, no name', w.ctl.state === 'busy' && /about 10 minutes/.test(text(w, 'rb-overlay-text')) && text(w, 'rb-action') === 'Try again');
    w = mk();
    w.route('POST /api/rbrowser/session', json(409, { busy: true }));
    await w.ctl.start();
    check('busy without an estimate has a plain sentence', w.ctl.state === 'busy' && /in a little while/.test(text(w, 'rb-overlay-text')));
    w = mk();
    w.route('POST /api/rbrowser/session', json(403, {}));
    await w.ctl.start();
    check('create 403 is "not allowed"', w.ctl.state === 'not_allowed');
    w = mk();
    w.route('POST /api/rbrowser/session', json(429, {}));
    await w.ctl.start();
    check('create 429 says wait', w.ctl.state === 'error' && /Wait a few minutes/.test(text(w, 'rb-overlay-text')) && w.pending().length === 0);
    w = mk();
    w.route('POST /api/rbrowser/session', json(503, { retry_after: 10 }));
    w.route('GET /api/rbrowser/status', [status(), status({ checking: true })]);
    await w.ctl.start();
    check('create 503 with retry_after: "Checking the browser sandbox" and a retry in that time', w.ctl.state === 'checking' && w.pending().join() === '10000', w.pending().join());
    w = mk();
    w.route('POST /api/rbrowser/session', json(503, { error: 'x' }));
    await w.ctl.start();
    check('create 503 without retry_after is a start failure: error text, no retry loop', w.ctl.state === 'error' && w.pending().length === 0 && /could not be started/.test(text(w, 'rb-overlay-title')));
    await w.advance(120000);
    check('... and nothing happens afterwards', w.calls.filter(c => c.method === 'POST').length === 1);

    // another sign-in's session, then takeover
    w = world();
    w.route('GET /api/rbrowser/status', status());
    w.route('GET /api/rbrowser/session', json(409, { elsewhere: true }));
    w.route('POST /api/rbrowser/session', json(201, sessionInfo(w)));
    await w.ctl.start();
    check('a session of another sign-in offers "End it and start here" and creates nothing yet',
      w.ctl.state === 'elsewhere' && text(w, 'rb-action') === 'End it and start here' && !w.calls.some(c => c.method === 'POST'));
    await w.els['rb-action'].click();
    const post = w.calls.filter(c => c.method === 'POST')[0];
    check('the button creates with takeover: true', post && post.body.takeover === true && w.sockets.length === 1, JSON.stringify(post));
    w = mk();
    w.route('POST /api/rbrowser/session', [json(409, { elsewhere: true }), json(201, sessionInfo(w))]);
    await w.ctl.start();
    check('create answering 409 elsewhere gets the same offer', w.ctl.state === 'elsewhere');
    await w.els['rb-action'].click();
    const posts = w.calls.filter(c => c.method === 'POST');
    check('the first create has no takeover, the second has', posts.length === 2 && posts[0].body.takeover === undefined && posts[1].body.takeover === true);
  });

  // ---- close codes ----
  await withDeadline('close codes', async () => {
    // network closes: 1 s, 2 s, 5 s, then a button
    for (const code of [1006, 1001]) {
      const w = world();
      await connect(w);
      w.sockets[0].fireClose(code, '');
      check('close ' + code + ': reconnecting, first retry in 1 s', w.ctl.state === 'reconnecting' && w.pending().join() === '1000' && /attempt 1 of 3/.test(text(w, 'rb-overlay-text')), w.pending().join());
      const delays = [];
      for (let i = 0; i < 3; i++) {
        const before = w.sockets.length;
        await w.advance(w.pending()[0]);
        if (w.sockets.length > before) { w.sockets[w.sockets.length - 1].fireClose(code, ''); }
        delays.push(w.pending().join());
      }
      check('close ' + code + ': retries wait 1 s, 2 s, 5 s, then stop', w.sockets.length === 4 && delays.join('|') === '2000|5000|', delays.join('|') + ' sockets=' + w.sockets.length);
      check('close ' + code + ': after three tries a Reconnect button is shown and no timer is left', w.ctl.state === 'lost' && text(w, 'rb-action') === 'Reconnect' && w.pending().length === 0);
    }
    // a reconnect that succeeds resets the count
    let w = world();
    await connect(w);
    w.sockets[0].fireClose(1006, '');
    await w.advance(1000);
    w.rfbs[w.rfbs.length - 1].emit('connect');
    w.sockets[w.sockets.length - 1].fireClose(1006, '');
    check('after a successful reconnect the next loss starts again at 1 s', w.ctl.state === 'reconnecting' && w.pending().join() === '1000', w.pending().join());
    // the lost state's button resumes
    w = world();
    await connect(w);
    w.sockets[0].fireClose(1006, '');
    for (let i = 0; i < 3; i++) { await w.advance(w.pending()[0]); w.sockets[w.sockets.length - 1].fireClose(1006, ''); }
    const n = w.sockets.length;
    await w.els['rb-action'].click();
    check('Reconnect looks at the session and attaches again', w.sockets.length === n + 1);
    // a gone session while reconnecting is not recreated
    w = world();
    await connect(w);
    w.route('GET /api/rbrowser/session', json(404, {}));
    w.sockets[0].fireClose(1006, '');
    const posts0 = w.calls.filter(c => c.method === 'POST' && c.url === '/api/rbrowser/session').length;
    await w.advance(1000);
    check('reconnect never starts a new session on its own: 404 is "ended"', w.ctl.state === 'ended' && w.calls.filter(c => c.method === 'POST' && c.url === '/api/rbrowser/session').length === posts0 && text(w, 'rb-action') === 'Start again');

    // terminal codes
    const terminal = [
      [4012, '', 'other_window', 'Use this window'],
      [4013, 'idle', 'ended', 'Start again'],
      [4013, 'admin_end', 'ended', 'Start again'],
      [4004, 'no such session', 'ended', 'Start again'],
      [4003, '', 'not_allowed', 'Back to the dashboard'],
    ];
    for (const [code, reason, state, button] of terminal) {
      const x = world();
      await connect(x);
      const calls = x.calls.length, socks = x.sockets.length;
      x.sockets[0].fireClose(code, reason);
      await x.advance(120000);
      check('close ' + code + (reason ? ' "' + reason + '"' : '') + ': state ' + state + ', button "' + button + '", no reconnect, no timer, no new request',
        x.ctl.state === state && text(x, 'rb-action') === button && x.sockets.length === socks && x.calls.length === calls && x.pending().length === 0,
        x.ctl.state + ' ' + text(x, 'rb-action') + ' calls ' + (x.calls.length - calls));
    }
    let x = world();
    await connect(x);
    x.sockets[0].fireClose(4013, 'idle');
    check('4013 idle shows the sentence for idle', /idle for too long/.test(text(x, 'rb-overlay-text')), text(x, 'rb-overlay-text'));
    x = world();
    await connect(x);
    x.sockets[0].fireClose(4013, '<img src=x onerror=alert(1)>');
    check('4013 with an unknown reason shows the fallback and never the server text', text(x, 'rb-overlay-text') === 'The session ended.' && innerHtmlWrites.length === 0);
    x = world();
    await connect(x);
    x.sockets[0].fireClose(4013, 'slow');
    check('4013 slow offers Reconnect (the session still exists)', x.ctl.state === 'ended' && text(x, 'rb-action') === 'Reconnect' && x.pending().length === 0);
    x = world();
    await connect(x);
    x.sockets[0].fireClose(4012, '');
    check('4012 says the session is open in another window', /another window/.test(text(x, 'rb-overlay-title')));
    const nsock = x.sockets.length;
    await x.els['rb-action'].click();
    check('"Use this window" attaches here again', x.sockets.length === nsock + 1);
    x = world();
    await connect(x);
    x.sockets[0].fireClose(4001, '');
    check('close 4001 goes to /login without a reconnect', x.assigned.join() === '/login' && x.pending().length === 0);
    x = world();
    await connect(x);
    x.sockets[0].fireClose(4503, '');
    check('close 4503 is maintenance, no automatic reconnect', x.ctl.state === 'maintenance' && x.pending().length === 0);
    x = world();
    await connect(x);
    x.sockets[0].fireClose(1000, '');
    check('any other close code is not retried automatically', x.ctl.state === 'closed' && x.pending().length === 0 && text(x, 'rb-action') === 'Reconnect');
    x = world();
    await connect(x);
    x.rfbs[0].emit('disconnect', { clean: false });
    check('noVNC giving up without a socket close counts as a lost connection', x.ctl.state === 'reconnecting');
  });

  // ---- boot id ----
  await withDeadline('boot id', async () => {
    const store = new Map();
    let w = world({ store });
    await connect(w, {}, 'boot-A');
    check('the boot id is remembered once a session is attached', store.get('rbrowser.boot') === 'boot-A');
    const w2 = world({ store });
    w2.route('GET /api/rbrowser/status', status({ boot_id: 'boot-B' }));
    w2.route('GET /api/rbrowser/session', json(404, {}));
    w2.route('POST /api/rbrowser/session', json(201, sessionInfo(w2)));
    await w2.ctl.start();
    check('a session gone and a changed boot id: "The portal was restarted. Start a new session."',
      w2.ctl.state === 'restarted' && text(w2, 'rb-overlay-text') === 'The portal was restarted. Start a new session.' && w2.sockets.length === 0 && !w2.calls.some(c => c.method === 'POST'));
    check('... the hint is used up', !store.has('rbrowser.boot'));
    await w2.els['rb-action'].click();
    check('... and the button starts a new session', w2.sockets.length === 1);
    const same = new Map([['rbrowser.boot', 'boot-A']]);
    const w3 = world({ store: same });
    w3.route('GET /api/rbrowser/status', status({ boot_id: 'boot-A' }));
    w3.route('GET /api/rbrowser/session', json(404, {}));
    w3.route('POST /api/rbrowser/session', json(201, sessionInfo(w3)));
    await w3.ctl.start();
    check('the same boot id and no session just starts one', w3.ctl.state !== 'restarted' && w3.sockets.length === 1);
    const w4 = world({ store: new Map() });
    w4.route('GET /api/rbrowser/status', status({ boot_id: 'boot-B' }));
    w4.route('GET /api/rbrowser/session', json(404, {}));
    w4.route('POST /api/rbrowser/session', json(201, sessionInfo(w4)));
    await w4.ctl.start();
    check('no remembered session: no restart message', w4.ctl.state !== 'restarted' && w4.sockets.length === 1);
    // lost connection, then the portal came back with a new boot id
    const st = new Map();
    const w5 = world({ store: st });
    await connect(w5, {}, 'boot-A');
    w5.route('GET /api/rbrowser/session', json(404, {}));
    w5.route('GET /api/rbrowser/status', status({ boot_id: 'boot-B' }));
    w5.sockets[0].fireClose(1006, '');
    await w5.advance(1000);
    check('a reconnect that finds the session gone after a restart says so', w5.ctl.state === 'restarted', w5.ctl.state);
    const w6 = world({ storageThrows: true });
    happy(w6);
    await w6.ctl.start();
    check('storage that refuses is survived', w6.sockets.length === 1);
  });

  // ---- idle, lifetime and traffic warnings ----
  await withDeadline('warnings', async () => {
    let w = world();
    w = world();
    await connect(w);
    await w.advance(5000);
    check('far from the deadline there is no idle warning', !vis(w, 'rb-banner-idle') && !vis(w, 'rb-banner-life') && !vis(w, 'rb-banner-traffic'));
    // idle deadline 70 s away; the server's real deadline is the same
    w = world();
    await connect(w, { idle_deadline: 1700000000 + 70 });
    w.route('GET /api/rbrowser/session', json(200, sessionInfo(w, { idle_deadline: 1700000000 + 70 })));
    await w.advance(20000);
    check('inside the last 60 s "Still there?" shows with a countdown and the I am here button', vis(w, 'rb-banner-idle') && /^Still there\?/.test(text(w, 'rb-banner-idle-text')) && /ends in \d+ seconds/.test(text(w, 'rb-banner-idle-text')), text(w, 'rb-banner-idle-text'));
    const before = w.calls.filter(c => c.method === 'GET' && c.url === '/api/rbrowser/session').length;
    await w.els['rb-here'].click();
    check('"I am here" sends the control frame as a text frame on the session socket', w.sockets[0].sent.length === 1 && w.sockets[0].sent[0] === '{"op":"here"}', JSON.stringify(w.sockets[0].sent));
    check('... and hides the warning at once', !vis(w, 'rb-banner-idle'));
    w.route('GET /api/rbrowser/session', json(200, sessionInfo(w, { idle_deadline: 1700000000 + 20 + 900 })));
    await w.advance(2000);
    check('... the deadline is read again and the warning stays away', w.calls.filter(c => c.method === 'GET' && c.url === '/api/rbrowser/session').length > before && !vis(w, 'rb-banner-idle'));
    // activity moved the deadline: no warning
    w = world();
    await connect(w, { idle_deadline: 1700000000 + 70 });
    w.route('GET /api/rbrowser/session', json(200, sessionInfo(w, { idle_deadline: 1700000000 + 900 })));
    await w.advance(20000);
    check('a deadline that the server moved on (key or pointer activity) shows no warning', !vis(w, 'rb-banner-idle'));
    // lifetime
    w = world();
    await connect(w, { max_deadline: 1700000000 + 200 });
    await w.advance(2000);
    check('five minutes before the lifetime ends a warning shows the minutes', vis(w, 'rb-banner-life') && /about 4 minutes/.test(text(w, 'rb-banner-life-text')), text(w, 'rb-banner-life-text'));
    // traffic
    w = world();
    await connect(w);
    w.route('GET /api/rbrowser/session', json(200, sessionInfo(w, { net_warning: true })));
    await w.advance(16000);
    check('net_warning shows the traffic warning', vis(w, 'rb-banner-traffic') && /data allowance/.test(text(w, 'rb-banner-traffic-text')));
    // polling stops with the socket
    await (async () => { w.sockets[0].fireClose(4013, 'idle'); const n = w.calls.length; await w.advance(60000); check('polling stops when the session ends', w.calls.length === n && !vis(w, 'rb-banner-traffic')); })();
  });

  // ---- resize, quality, fit ----
  await withDeadline('toolbar', async () => {
    let w = world();
    await connect(w);
    await w.advance(100);
    let posts = () => w.calls.filter(c => c.url === '/api/rbrowser/session/resize');
    check('the size is sent once after connecting', posts().length === 1 && JSON.stringify(posts()[0].body) === '{"width":992,"height":688}', JSON.stringify(posts()));
    const fire = () => w.win.listeners.resize.forEach(f => f());
    w.els['rb-stage'].clientWidth = 1280; w.els['rb-stage'].clientHeight = 768;
    fire(); await w.advance(200); fire(); await w.advance(200); fire();
    await w.advance(499);
    check('window resizes are debounced for 500 ms', posts().length === 1);
    await w.advance(2);
    check('... then one POST with the clamped size', posts().length === 2 && JSON.stringify(posts()[1].body) === '{"width":1280,"height":768}', JSON.stringify(posts()));
    fire(); await w.advance(600);
    check('an unchanged size sends nothing', posts().length === 2);
    w.els['rb-stage'].clientWidth = 300; w.els['rb-stage'].clientHeight = 300;
    fire(); await w.advance(600);
    check('a tiny window is clamped up to the minimum size', JSON.stringify(posts()[2].body) === JSON.stringify({ width: 560, height: 480 }), JSON.stringify(posts()[2]));
    w.route('POST /api/rbrowser/session/resize', json(429, {}));
    w.els['rb-stage'].clientWidth = 800; fire(); await w.advance(600);
    check('a refused resize is ignored', w.ctl.state === 'connected');
    // keyboard open: no resize
    w.els['rb-keyboard'].fire('click');
    const k = posts().length;
    w.els['rb-stage'].clientHeight = 500; fire(); await w.advance(600);
    check('while the phone keyboard is open the window is not resized', posts().length === k);
    w.els['rb-kbd'].blur(); await w.advance(600);
    check('... and it is when the keyboard closes', posts().length === k + 1);

    // quality
    w = world();
    await connect(w);
    const sel = w.els['rb-quality'];
    check('the quality list has Low, Balanced and Sharp, Balanced selected', sel.children.map(c => c.textContent).join() === 'Low,Balanced,Sharp' && sel.value === 'balanced');
    sel.value = 'sharp'; sel.fire('change');
    check('choosing Sharp sets the pair and remembers it', w.rfbs[0].qualityLevel === 9 && w.rfbs[0].compressionLevel === 0 && w.store.get('rbrowser.quality') === 'sharp');
    sel.value = 'low'; sel.fire('change');
    check('choosing Low sets its pair', w.rfbs[0].qualityLevel === 2 && w.rfbs[0].compressionLevel === 7);
    const w2 = world({ store: new Map([['rbrowser.quality', 'sharp']]) });
    await connect(w2);
    check('a remembered quality is applied to the next session', w2.els['rb-quality'].value === 'sharp' && w2.rfbs[0].qualityLevel === 9);
    const w3 = world({ store: new Map([['rbrowser.quality', 'bogus']]) });
    await connect(w3);
    check('an unknown remembered value falls back to the default', w3.rfbs[0].qualityLevel === 6);
    const w4 = world({ storageThrows: true });
    await connect(w4);
    w4.els['rb-quality'].value = 'low'; w4.els['rb-quality'].fire('change');
    check('storage that refuses does not stop the quality choice', w4.rfbs[0].qualityLevel === 2);

    // fit
    w = world();
    await connect(w);
    check('Fit is the start mode', w.rfbs[0].scaleViewport === true && text(w, 'rb-fit') === 'Fit');
    await w.els['rb-fit'].click();
    check('1:1 turns scaling off and clips the viewport', w.rfbs[0].scaleViewport === false && w.rfbs[0].clipViewport === true && text(w, 'rb-fit') === '1:1');
    await w.els['rb-fit'].click();
    check('and back to Fit', w.rfbs[0].scaleViewport === true && w.rfbs[0].clipViewport === false);
    await w.els['rb-fullscreen'].click();
    check('Fullscreen asks the page for fullscreen', w.fullscreen === true);
    const wf = world({ fullscreen: false });
    await connect(wf);
    check('no Fullscreen button where the browser has none (iPhone)', !vis(wf, 'rb-fullscreen'));
    await w.els['rb-about'].click();
    check('About opens the panel', vis(w, 'rb-about-panel'));
    await w.els['rb-about-close'].click();
    check('... and Close shuts it', !vis(w, 'rb-about-panel'));
  });

  // ---- End session ----
  await withDeadline('end', async () => {
    let w = world();
    await connect(w);
    const dels = () => w.calls.filter(c => c.method === 'DELETE').length;
    await w.els['rb-end'].click();
    check('End opens an inline question in its own panel and hides the End button (the click lands on nothing)', vis(w, 'rb-confirm') && !vis(w, 'rb-end'));
    await w.els['rb-end-yes'].click();
    check('a confirm click right after the question opened is ignored', dels() === 0);
    await w.advance(700);
    await w.els['rb-end-yes'].click({ detail: 2 });
    check('the second click of a double click is ignored', dels() === 0);
    w.route('DELETE /api/rbrowser/session', json(204));
    const p1 = w.els['rb-end-yes'].click();
    const p2 = w.els['rb-end-yes'].click();
    await Promise.all([p1, p2]);
    check('one End request is sent, whatever the number of clicks while it runs', dels() === 1, dels());
    check('the session is shown as ended, with the "You ended this session." sentence and a Start again button', w.ctl.state === 'ended' && text(w, 'rb-overlay-text') === 'You ended this session.' && text(w, 'rb-action') === 'Start again');
    const sockCount = w.sockets.length, callCount = w.calls.length;
    w.sockets[0].fireClose(4013, 'closed');
    await w.advance(60000);
    check('the 4013 "closed" that follows is not a network close: no reconnect, no request', w.sockets.length === sockCount && w.calls.length === callCount && w.pending().length === 0);
    // a failing End keeps the question open and allows another try
    w = world();
    await connect(w);
    await w.els['rb-end'].click();
    await w.advance(700);
    w.route('DELETE /api/rbrowser/session', [json(500, {}), json(204)]);
    await w.els['rb-end-yes'].click();
    check('a failed End says so and keeps the session', w.ctl.state === 'connected' && vis(w, 'rb-confirm') && vis(w, 'rb-confirm-msg') && !w.els['rb-end-yes'].disabled);
    await w.els['rb-end-yes'].click();
    check('... the next try works', w.ctl.state === 'ended');
    w = world();
    await connect(w);
    await w.els['rb-end'].click();
    await w.els['rb-end-no'].click();
    check('"Keep it" closes the question and brings the End button back', !vis(w, 'rb-confirm') && vis(w, 'rb-end') && w.calls.filter(c => c.method === 'DELETE').length === 0);
    // a close that arrives while the End request is running does not decide the state
    w = world();
    await connect(w);
    await w.els['rb-end'].click();
    await w.advance(700);
    w.route('DELETE /api/rbrowser/session', json(204));
    const pe = w.els['rb-end-yes'].click();
    w.sockets[0].fireClose(4013, 'closed');
    await pe;
    check('a socket close during the End request leaves the outcome to the request', w.ctl.state === 'ended' && text(w, 'rb-overlay-text') === 'You ended this session.');
  });

  // ---- typing ----
  await withDeadline('typing', async () => {
    let w = world();
    await connect(w);
    const rfb = w.rfbs[0];
    let r = await w.ctl.typeText('Hi é€\u{1F600}\n\t');
    check('typeText sends each key as a press and release with the mapped keysym, no scan code',
      hex(sent(rfb)) === '48,69,20,e9,10020ac,101f600,ff0d,ff09' && rfb.keys.every(k => k[1] === null && k[2] === undefined) && r.ok && r.sent === 8, hex(sent(rfb)));
    rfb.keys.length = 0;
    const long = 'x'.repeat(100);
    const done = w.ctl.typeText(long);
    check('the first chunk of 40 goes at once', rfb.keys.length === 40, rfb.keys.length);
    await w.advance(29);
    check('... the next one waits for the interval (30 ms)', rfb.keys.length === 40);
    await w.advance(1);
    check('... and follows after it', rfb.keys.length === 80);
    await w.advance(30);
    const res = await done;
    check('the whole text arrives in order, 40 + 40 + 20', rfb.keys.length === 100 && res.ok && res.sent === 100);
    rfb.keys.length = 0;
    const a = w.ctl.typeText('a'.repeat(50));
    const b = w.ctl.typeText('b');
    await w.advance(100);
    await Promise.all([a, b]);
    check('two calls are typed one after the other, not interleaved', sent(rfb).length === 51 && sent(rfb).slice(0, 50).every(x => x === 0x61) && sent(rfb)[50] === 0x62);
    rfb.keys.length = 0;
    r = await w.ctl.typeText('y'.repeat(5001));
    check('more than 5000 characters: nothing is sent and the page says so', !r.ok && r.reason === 'too_long' && rfb.keys.length === 0 && /at most 5000/.test(text(w, 'rb-text-msg')));
    const five = w.ctl.typeText('z'.repeat(5000));
    await w.advance(5000);
    r = await five;
    check('exactly 5000 characters are accepted', r.ok && r.sent === 5000 && rfb.keys.length === 5000);
    rfb.keys.length = 0;
    const emoji = w.ctl.typeText('\u{1F600}'.repeat(5000));
    await w.advance(5000);
    r = await emoji;
    check('the limit counts characters, not UTF-16 units: 5000 emoji pass', r.ok && r.sent === 5000, JSON.stringify(r));
    rfb.keys.length = 0;
    const cut = w.ctl.typeText('c'.repeat(200));
    w.sockets[0].fireClose(1006, '');
    r = await cut;
    check('closing the socket drops a queued text and says cancelled', !r.ok && r.reason === 'cancelled');
    const w2 = world();
    r = await w2.ctl.typeText('hello');
    check('without a connection nothing is typed', !r.ok && r.reason === 'not_connected');
  });

  // ---- paste ----
  await withDeadline('paste', async () => {
    const w = world();
    await connect(w);
    const rfb = w.rfbs[0];
    let e = w.key(w.canvas, { ctrlKey: true, key: 'v', code: 'KeyV' });
    check('Ctrl+V on the picture is withheld from noVNC and not cancelled (so the paste event fires)', w.novncKeys === 0 && e.stopped && !e.defaultPrevented);
    e = w.key(w.canvas, { metaKey: true, key: 'v', code: 'KeyV' });
    check('Cmd+V too', w.novncKeys === 0 && e.stopped && !e.defaultPrevented);
    e = w.key(w.canvas, { ctrlKey: true, key: 'V', code: 'KeyV', shiftKey: true });
    check('Ctrl+Shift+V too, also on another layout (the code, not the letter)', w.novncKeys === 0);
    e = w.key(w.canvas, { ctrlKey: true, key: 'c', code: 'KeyC' });
    check('Ctrl+C reaches noVNC', w.novncKeys === 1 && !e.stopped);
    e = w.key(w.canvas, { key: 'v', code: 'KeyV' });
    check('a plain v reaches noVNC', w.novncKeys === 2);
    e = w.key(w.canvas, { ctrlKey: true, altKey: true, key: 'v', code: 'KeyV' });
    check('Ctrl+Alt+V (AltGr combinations) reaches noVNC', w.novncKeys === 3);
    w.els['rb-textbox'].addEventListener('keydown', () => { w.novncKeys += 100; });
    e = w.key(w.els['rb-textbox'], { ctrlKey: true, key: 'v', code: 'KeyV' });
    check('Ctrl+V in the page\'s own text box is left alone', !e.stopped && w.novncKeys === 103);
    e = w.paste(w.canvas, 'päste €');
    await w.advance(100);
    check('the paste event is cancelled and the text is typed as key events', e.defaultPrevented && hex(sent(rfb)) === '70,e4,73,74,65,20,10020ac', hex(sent(rfb)));
    const rel = rfb.keys.filter(k => k[2] === false).map(k => k[0]);
    const firstTyped = rfb.keys.findIndex(k => k[2] === undefined);
    check('Control, Shift, Super and Meta are released before the text (the key combination already reached the remote)',
      [0xffe3, 0xffe4, 0xffe1, 0xffe2, 0xffeb, 0xffec].every(k => rel.indexOf(k) !== -1) && rfb.keys.slice(0, firstTyped).every(k => k[2] === false), JSON.stringify(rfb.keys.slice(0, 10)));
    rfb.keys.length = 0;
    e = w.paste(w.canvas, 'q'.repeat(100));
    await w.advance(200);
    const ups = rfb.keys.filter(k => k[2] === false && k[0] === 0xffe3).length;
    let typedSoFar = 0, upBeforeSecond = false, upBeforeThird = false;
    rfb.keys.forEach((k, i) => {
      if (k[2] === undefined) typedSoFar++;
      else if (k[0] === 0xffe3 && typedSoFar === 40) upBeforeSecond = true;
      else if (k[0] === 0xffe3 && typedSoFar === 80) upBeforeThird = true;
    });
    check('a long paste releases the modifiers again before each chunk of 40', ups === 3 && upBeforeSecond && upBeforeThird, 'ups=' + ups);
    rfb.keys.length = 0;
    e = w.paste(w.els['rb-textbox'], 'into the box');
    check('a paste into the text box is not intercepted', !e.defaultPrevented && rfb.keys.length === 0);
    e = w.paste(w.els['rb-kbd'], 'into the phone field');
    check('a paste into the phone keyboard field is not intercepted by the page handler', !e.defaultPrevented && rfb.keys.length === 0);
    e = w.paste(w.canvas, '');
    check('an empty paste types nothing', rfb.keys.length === 0);
    const idle = world();
    e = idle.paste(idle.canvas, 'abc');
    check('a paste before the session is connected types nothing and is not cancelled', !e.defaultPrevented && idle.rfbs.length === 0);
  });

  // ---- a refusal must be on the screen even when the text panel is shut ----
  await withDeadline('refusals on screen', async () => {
    const w = world();
    await connect(w);
    const rfb = w.rfbs[0];
    check('the markup walk finds the panel around the panel\'s message line', PARENT['rb-text-msg'] === 'rb-textpanel' && PARENT['rb-banner-msg'] === 'rb-banners', JSON.stringify([PARENT['rb-text-msg'], PARENT['rb-banner-msg']]));
    check('with the text panel shut, its message line is not on the screen (so it cannot be the only place a refusal goes)', !onScreen(w, 'rb-text-msg'));
    check('and the picture banner is not shown before anything is refused', !onScreen(w, 'rb-banner-msg'));
    const e = w.paste(w.canvas, 'x'.repeat(5001));
    await w.advance(100);
    check('a paste of more than 5000 characters is cancelled, nothing is typed, and the refusal is on the screen', e.defaultPrevented && rfb.keys.length === 0
      && onScreen(w, 'rb-banner-msg') && /at most 5000/.test(text(w, 'rb-banner-msg-text')) && /Nothing was sent/.test(text(w, 'rb-banner-msg-text')), text(w, 'rb-banner-msg-text'));
    await w.advance(7000);
    check('the refusal is still there after 7 seconds', onScreen(w, 'rb-banner-msg'));
    await w.advance(2000);
    check('and goes away after 8 seconds', !onScreen(w, 'rb-banner-msg'));
    w.paste(w.canvas, 'y'.repeat(5001));
    check('a second refusal shows again', onScreen(w, 'rb-banner-msg'));
    await w.els['rb-text-toggle'].click();
    check('opening the text panel shows the message there and takes the banner away', onScreen(w, 'rb-text-msg') && !onScreen(w, 'rb-banner-msg') && /at most 5000/.test(text(w, 'rb-text-msg')));
    w.paste(w.canvas, 'z'.repeat(5001));
    check('with the text panel open the refusal is in the panel and no banner is added', onScreen(w, 'rb-text-msg') && !onScreen(w, 'rb-banner-msg'));
    await w.els['rb-text-toggle'].click();
    // the phone keyboard path has no panel either
    await w.ctl.typeText('k'.repeat(5001));
    check('typeText from the phone keyboard path is refused on the screen as well', onScreen(w, 'rb-banner-msg'));
    w.rfbs[0].emit('disconnect', { clean: false });
    await flush();
    check('a lost connection takes the banner away (the overlay speaks then)', !onScreen(w, 'rb-banner-msg'));
  });

  // ---- the phone keyboard ----
  await withDeadline('phone keyboard', async () => {
    let w = world();
    await connect(w);
    const rfb = w.rfbs[0];
    const kbd = w.els['rb-kbd'];
    await w.els['rb-keyboard'].click();
    check('the Keyboard button focuses the hidden text area', kbd.focusCalls === 1 && kbd.focused);
    // a cancelled beforeinput makes no input event, as in a browser
    const bi = (type, data, extra) => { const e = ev(Object.assign({ inputType: type, data, isComposing: false }, extra)); kbd.fire('beforeinput', e); if (!e.defaultPrevented) kbd.fire('input', ev({ inputType: type, data, isComposing: false })); return e; };
    let e = bi('insertText', 'h');
    check('insertText types the character exactly once (beforeinput and input do not both fire it)', hex(sent(rfb)) === '68' && e.defaultPrevented, hex(sent(rfb)));
    rfb.keys.length = 0;
    bi('insertText', '€');
    check('a character above Latin-1 is typed once', hex(sent(rfb)) === '10020ac');
    rfb.keys.length = 0;
    bi('deleteContentBackward', null);
    check('deleteContentBackward is one BackSpace', hex(sent(rfb)) === 'ff08');
    rfb.keys.length = 0;
    bi('insertLineBreak', null);
    check('insertLineBreak (Enter on Android) is one Return', hex(sent(rfb)) === 'ff0d');
    rfb.keys.length = 0;
    e = w.key(kbd, { key: 'Enter', keyCode: 13 });
    check('Enter on a physical or iOS keyboard is one Return and the default is cancelled (no second beforeinput)', hex(sent(rfb)) === 'ff0d' && e.defaultPrevented);
    rfb.keys.length = 0;
    e = w.key(kbd, { key: 'Backspace', keyCode: 8 });
    check('Backspace key is one BackSpace', hex(sent(rfb)) === 'ff08' && e.defaultPrevented);
    rfb.keys.length = 0;
    e = w.key(kbd, { key: 'Unidentified', keyCode: 229 });
    check('an Android "Unidentified" key (229) is left to beforeinput', rfb.keys.length === 0 && !e.defaultPrevented);
    e = w.key(kbd, { key: 'a', keyCode: 65 });
    check('a printable key is left to the input events (no double typing)', rfb.keys.length === 0 && !e.defaultPrevented);
    e = w.key(kbd, { key: 'v', ctrlKey: true, keyCode: 86 });
    check('a shortcut in the field is not turned into a key', rfb.keys.length === 0);
    // composition
    kbd.fire('compositionstart', ev({}));
    kbd.fire('beforeinput', ev({ inputType: 'insertCompositionText', data: 'hé', isComposing: true }));
    kbd.fire('beforeinput', ev({ inputType: 'insertText', data: 'x', isComposing: true }));
    kbd.fire('input', ev({ inputType: 'insertCompositionText', data: 'hé', isComposing: true }));
    check('while composing nothing is typed', rfb.keys.length === 0);
    kbd.value = 'héllo';
    kbd.fire('compositionend', ev({ data: 'héllo' }));
    kbd.fire('input', ev({ inputType: 'insertCompositionText', data: 'héllo', isComposing: false }));
    check('compositionend types the composed text once', hex(sent(rfb)) === '68,e9,6c,6c,6f', hex(sent(rfb)));
    check('the field is emptied afterwards', kbd.value === '');
    rfb.keys.length = 0;
    // regression: a space (insertText) and then the next word's composition must not clear the field under the IME
    bi('insertText', ' ');
    rfb.keys.length = 0;
    kbd.fire('compositionstart', ev({}));
    kbd.value = 'w';
    kbd.fire('beforeinput', ev({ inputType: 'insertCompositionText', data: 'w', isComposing: true }));
    kbd.fire('input', ev({ inputType: 'insertCompositionText', data: 'w', isComposing: true }));
    kbd.value = 'wo';
    kbd.fire('input', ev({ inputType: 'insertCompositionText', data: 'wo', isComposing: true }));
    check('after a space, the next word is composed in the field without it being cleared', kbd.value === 'wo' && rfb.keys.length === 0, kbd.value);
    kbd.fire('compositionend', ev({ data: 'wo' }));
    check('... and the word is typed once at the end', hex(sent(rfb)) === '77,6f' && kbd.value === '', hex(sent(rfb)));
    rfb.keys.length = 0;
    // a browser without beforeinput
    const wn = world({ beforeInput: false });
    await connect(wn);
    const k2 = wn.els['rb-kbd'];
    k2.value = 'q';
    k2.fire('input', ev({ inputType: 'insertText', data: 'q', isComposing: false }));
    check('without beforeinput the input event types the character once and empties the field', hex(sent(wn.rfbs[0])) === '71' && k2.value === '');
    k2.fire('input', ev({ inputType: 'deleteContentBackward', data: null, isComposing: false }));
    check('... and handles deletes', hex(sent(wn.rfbs[0])) === '71,ff08');
    // ordering of typed text and a delete
    rfb.keys.length = 0;
    bi('insertText', 'abc');
    bi('deleteContentBackward', null);
    await w.advance(50);
    check('text and a following BackSpace keep their order', hex(sent(rfb)) === '61,62,63,ff08', hex(sent(rfb)));
    await w.els['rb-keyboard'].click();
    check('the Keyboard button again closes the keyboard', !kbd.focused);
  });

  // ---- text box and copying from the browser ----
  const CLIP = 'POST /api/rbrowser/session/clipboard';
  const clipCalls = (w) => w.calls.filter(c => c.url === '/api/rbrowser/session/clipboard');
  await withDeadline('text box', async () => {
    let w = world();
    await connect(w);
    const rfb = w.rfbs[0];
    check('the page never listens for the noVNC clipboard event', rfb.listeners.clipboard === undefined);
    check('mode both: the Text button and "Copy from the browser" are there, "Put on the remote clipboard" is gone', vis(w, 'rb-text-toggle') && !('rb-put-clip' in w.els) && !('rb-clip-hint' in w.els) && w.els['rb-get-clip'] && !w.els['rb-get-clip'].hidden);
    await w.els['rb-text-toggle'].click();
    check('the Text button opens the panel', vis(w, 'rb-textpanel') && w.els['rb-text-toggle'].attrs['aria-expanded'] === 'true');
    check('before anything is copied the received box is not shown', !onScreen(w, 'rb-received-wrap'));
    const box = w.els['rb-textbox'];
    box.value = 'Send me €';
    box.fire('input');
    const sendP = w.els['rb-send-text'].click();
    await w.advance(100);
    await sendP;
    check('Send text types the text and empties the box', hex(sent(rfb)) === '53,65,6e,64,20,6d,65,20,10020ac' && box.value === '' && /Sent 9 characters/.test(text(w, 'rb-text-msg')), hex(sent(rfb)) + ' ' + text(w, 'rb-text-msg'));
    check('nothing was handed to the noVNC clipboard', rfb.pasted.length === 0);
    // copy from the browser
    w.route(CLIP, json(200, { text: '<img src=x onerror=alert(1)>', truncated: false }));
    await w.els['rb-get-clip'].click();
    check('"Copy from the browser" asks POST /api/rbrowser/session/clipboard once, with no text in the request', clipCalls(w).length === 1 && clipCalls(w)[0].method === 'POST' && JSON.stringify(clipCalls(w)[0].body) === '{}', JSON.stringify(clipCalls(w)));
    check('the text is shown as text, with a Copy button, and not built into HTML', onScreen(w, 'rb-received-wrap') && text(w, 'rb-received') === '<img src=x onerror=alert(1)>' && innerHtmlWrites.length === 0);
    check('... and the button is usable again', !w.els['rb-get-clip'].disabled && /Text copied from the browser/.test(text(w, 'rb-text-msg')), text(w, 'rb-text-msg'));
    await w.els['rb-copy'].click();
    check('Copy writes it to the device clipboard', w.clipWrites.join('|') === '<img src=x onerror=alert(1)>');
    check('nothing was handed to the noVNC clipboard by copying either', rfb.pasted.length === 0);
    check('nothing is kept in storage or on the console', [...w.store.keys()].every(k => k === 'rbrowser.boot' || k === 'rbrowser.quality') && ![...w.store.values()].some(v => /onerror/.test(v)));
    // truncated
    w.route(CLIP, json(200, { text: 'long text', truncated: true }));
    await w.els['rb-get-clip'].click();
    check('a cut text is shown and the page says it was cut', text(w, 'rb-received') === 'long text' && /262144 bytes and was cut/.test(text(w, 'rb-text-msg')), text(w, 'rb-text-msg'));
    // empty
    w.route(CLIP, json(200, { text: '', truncated: false }));
    await w.els['rb-get-clip'].click();
    check('an empty clipboard clears the box and says so', !onScreen(w, 'rb-received-wrap') && text(w, 'rb-received') === '' && /no text copied/.test(text(w, 'rb-text-msg')));
    // refusals and failures
    w.route(CLIP, json(200, { text: 'kept?', truncated: false }));
    await w.els['rb-get-clip'].click();
    w.route(CLIP, json(403, { error: 'off' }));
    await w.els['rb-get-clip'].click();
    check('403: a short message, the earlier text stays as it was', /switched off/.test(text(w, 'rb-text-msg')) && text(w, 'rb-received') === 'kept?', text(w, 'rb-text-msg'));
    w.route(CLIP, json(429, {}));
    await w.els['rb-get-clip'].click();
    check('429: a short message to wait', /Wait a moment/.test(text(w, 'rb-text-msg')), text(w, 'rb-text-msg'));
    w.route(CLIP, 'throw');
    await w.els['rb-get-clip'].click();
    check('a network failure: a short message and the button is usable again', /could not be copied/.test(text(w, 'rb-text-msg')) && !w.els['rb-get-clip'].disabled, text(w, 'rb-text-msg'));
    w.route(CLIP, json(503, {}));
    await w.els['rb-get-clip'].click();
    check('any other status is a failure message too', /could not be copied/.test(text(w, 'rb-text-msg')));
    w.route(CLIP, json(200, { text: 5, truncated: false }));
    await w.els['rb-get-clip'].click();
    check('an answer without a text string is a failure, not shown', /could not be copied/.test(text(w, 'rb-text-msg')) && text(w, 'rb-received') === 'kept?');
    w.route(CLIP, json(401, {}));
    await w.els['rb-get-clip'].click();
    check('401 goes to the sign-in page', w.assigned.join() === '/login');

    // in-flight guard
    w = world();
    await connect(w);
    await w.els['rb-text-toggle'].click();
    let release;
    w.route(CLIP, new Promise((res) => { release = () => res(json(200, { text: 'late', truncated: false })); }));
    const first = w.els['rb-get-clip'].click();
    await flush();
    check('while a copy is in flight the button is disabled', w.els['rb-get-clip'].disabled === true);
    w.els['rb-get-clip'].fire('click', { detail: 1 });
    w.els['rb-get-clip'].fire('click', { detail: 1 });
    await flush();
    check('a second and third click while it is in flight send nothing', clipCalls(w).length === 1, clipCalls(w).length);
    release();
    await first;
    await flush();
    check('the answer lands once and the button is free again', text(w, 'rb-received') === 'late' && !w.els['rb-get-clip'].disabled && clipCalls(w).length === 1);
    // the session ends while a copy is in flight
    w = world();
    await connect(w);
    await w.els['rb-text-toggle'].click();
    w.route(CLIP, new Promise((res) => { release = () => res(json(200, { text: 'from a dead session', truncated: false })); }));
    const second = w.els['rb-get-clip'].click();
    await flush();
    w.sockets[0].fireClose(4013, 'idle');
    release();
    await second;
    await flush();
    check('text that arrives after the session ended is dropped', text(w, 'rb-received') === '' && !onScreen(w, 'rb-received-wrap') && !w.els['rb-get-clip'].disabled);
    // the text goes away with the session
    w = world();
    await connect(w);
    w.route(CLIP, json(200, { text: 'secret', truncated: false }));
    await w.els['rb-get-clip'].click();
    check('(the text is there)', text(w, 'rb-received') === 'secret');
    w.sockets[0].fireClose(4013, 'idle');
    check('the received text is cleared when the session ends', text(w, 'rb-received') === '' && w.ctl.received === '');

    // mode in (the server calls it to_browser): Send text only
    for (const mode of ['to_browser', 'in']) {
      w = world();
      await connect(w, { clipboard: mode });
      await w.els['rb-text-toggle'].click();
      check('mode ' + mode + ': the Text button and Send text are there, "Copy from the browser" and the received box are not', vis(w, 'rb-text-toggle') && onScreen(w, 'rb-send-text') && !onScreen(w, 'rb-get-clip') && !onScreen(w, 'rb-received-wrap') && w.ctl.clipMode === 'in');
      w.els['rb-textbox'].value = 'hi';
      await w.els['rb-send-text'].click();
      await w.advance(100);
      check('mode ' + mode + ': Send text types', hex(sent(w.rfbs[0])) === '68,69');
      const e = w.key(w.canvas, { ctrlKey: true, key: 'v', code: 'KeyV' });
      check('mode ' + mode + ': Ctrl+V still types a paste', w.novncKeys === 0 && e.stopped);
      await w.els['rb-get-clip'].click();
      check('mode ' + mode + ': a click on the hidden copy button asks nothing', clipCalls(w).length === 0);
    }

    // mode off: no text panel at all, no paste-as-typing, ordinary keys pass
    const wo = world();
    await connect(wo, { clipboard: 'off' });
    check('mode off: the Text button and the panel are not on the screen', !onScreen(wo, 'rb-text-toggle') && !onScreen(wo, 'rb-textpanel') && !onScreen(wo, 'rb-get-clip') && !onScreen(wo, 'rb-received-wrap'));
    check('mode off: the Keyboard button is still there', vis(wo, 'rb-keyboard'));
    await wo.els['rb-text-toggle'].click();
    check('mode off: a click on the hidden Text button opens nothing', !onScreen(wo, 'rb-textpanel'));
    wo.els['rb-textbox'].value = 'typed';
    await wo.els['rb-send-text'].click();
    await wo.advance(100);
    check('mode off: Send text types nothing', wo.rfbs[0].keys.length === 0 && wo.els['rb-textbox'].value === 'typed');
    await wo.els['rb-get-clip'].click();
    check('mode off: Copy from the browser asks nothing', clipCalls(wo).length === 0);
    let eo = wo.key(wo.canvas, { ctrlKey: true, key: 'v', code: 'KeyV' });
    check('mode off: Ctrl+V reaches noVNC as an ordinary key and is not cancelled', wo.novncKeys === 1 && !eo.stopped && !eo.defaultPrevented);
    eo = wo.key(wo.canvas, { metaKey: true, key: 'v', code: 'KeyV' });
    check('mode off: Cmd+V too', wo.novncKeys === 2 && !eo.stopped);
    eo = wo.key(wo.canvas, { key: 'a', code: 'KeyA' });
    check('mode off: an ordinary key reaches noVNC', wo.novncKeys === 3);
    eo = wo.paste(wo.canvas, 'pasted text');
    await wo.advance(100);
    check('mode off: a paste event types nothing', wo.rfbs[0].keys.length === 0 && !eo.defaultPrevented);
    const kbd = wo.els['rb-kbd'];
    const bi = (type, data, extra) => { const e = ev(Object.assign({ inputType: type, data, isComposing: false }, extra)); kbd.fire('beforeinput', e); return e; };
    bi('insertText', 'h');
    await wo.advance(100);
    check('mode off: the phone keyboard still types a character', hex(sent(wo.rfbs[0])) === '68');
    wo.rfbs[0].keys.length = 0;
    const pe = bi('insertFromPaste', 'pasted', {});
    await wo.advance(100);
    check('mode off: a paste into the phone keyboard field is refused with a message on the picture', wo.rfbs[0].keys.length === 0 && pe.defaultPrevented && onScreen(wo, 'rb-banner-msg') && /Pasting is switched off/.test(text(wo, 'rb-banner-msg-text')));
    const ro = await wo.ctl.typeText('still works');
    await wo.advance(100);
    check('typing works with the clipboard off', ro.ok === true && wo.rfbs[0].keys.length > 0);
    check('mode off: nothing was handed to noVNC\'s clipboard', wo.rfbs[0].pasted.length === 0 && wo.rfbs[0].listeners.clipboard === undefined);
    // an unknown value fails closed
    const wu = world();
    await connect(wu, { clipboard: 'something-new' });
    check('an unknown clipboard value counts as off', wu.ctl.clipMode === 'off' && !onScreen(wu, 'rb-text-toggle'));
    // the setting arrives with the status answer too
    const ws2 = world();
    ws2.route('GET /api/rbrowser/status', status({ clipboard: 'to_browser' }));
    ws2.route('GET /api/rbrowser/session', json(200, sessionInfo(ws2, { clipboard: undefined })));
    await ws2.ctl.start();
    ws2.rfbs[0].emit('connect');
    await flush();
    check('the status answer sets the mode when the session answer has none', ws2.ctl.clipMode === 'in' && vis(ws2, 'rb-text-toggle'));
    w = world();
    await connect(w);
    w.els['rb-textbox'].value = 'a';
    w.els['rb-text-toggle'].fire('click');
    w.sockets[0].fireClose(4013, 'idle');
    check('the panel and toolbar controls go away with the session', !vis(w, 'rb-textpanel') && !vis(w, 'rb-keyboard') && !vis(w, 'rb-end'));
  });

  if (process.argv[4] && process.argv[5]) {
    await adminCardChecks(process.argv[4]);
    await dashboardCardChecks(process.argv[5]);
  }

  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness crashed', ok: false, detail: e && e.stack })); });


// ---------------------------------------------------------------------------------------------------------------
// The admin card and the dashboard card. A tiny fake DOM (elements keep their children and their text only).
class N {
  constructor(tag) { this.tagName = String(tag).toUpperCase(); this.children = []; this.attrs = {}; this.listeners = {}; this.style = {}; this.className = ''; this.innerHTMLWrites = 0; this.value = ''; this.checked = false; this.hidden = false; this.href = ''; }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'class') this.className = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  async fire(t, e) { for (const f of (this.listeners[t] || [])) await f(e || {}); }
  set innerHTML(v) { this.innerHTMLWrites++; throw new Error('innerHTML must never be assigned'); }
  set textContent(v) { this.children = [{ tagName: '#text', text: String(v) }]; }
  get textContent() { return this.children.map(c => c.tagName === '#text' ? c.text : c.textContent).join(''); }
  find(pred, out = []) { if (pred(this)) out.push(this); for (const c of this.children) if (c.find) c.find(pred, out); return out; }
}
const btns = (n, label) => n.find(e => e.tagName === 'BUTTON' && (label === undefined || e.textContent === label));
const tick = async () => { for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r)); };

async function adminCardChecks(file) {
  const src = fs.readFileSync(file, 'utf8');
  const els = {};
  for (const id of ['rbrowser-admin-card', 'rbrowser-admin-note', 'rbrowser-admin-avail', 'rbrowser-admin-checks', 'rbrowser-admin-settings', 'rbrowser-admin-seats', 'rbrowser-admin-sessions']) els[id] = new N('DIV');
  els['rbrowser-admin-card'].style.display = 'none';
  const NOW = 1900000000000;
  let clock = NOW;
  const calls = [], toasts = [];
  let clipAnswer = 'both';
  let getStatus = 200, putStatus = 200, putBody = {}, endStatus = 200, release = null;
  const answer = () => ({
    settings: { rbrowser_enabled: true, rbrowser_min_role: 'user', rbrowser_max_sessions: 2, rbrowser_idle_minutes: 15, rbrowser_memory_mb: 2048,
      rbrowser_cpu_percent: 150, rbrowser_clipboard: clipAnswer, rbrowser_home_url: 'https://duckduckgo.com/', rbrowser_upload_kbps: 4000, rbrowser_extra_deny: ['10.0.0.0/8'] },
    availability: { available: false, missing: ['Xvfb', 'xrandr', 'xsel', 'matchbox-window-manager', 'weird name; rm -rf /'], reasons: ['Xvfb is not installed'], chromium_version: '131.0.1', chromium_age_days: 60, kernel_upload_limit: false },
    preflight: { ok: false, checks: [{ name: 'egress', ok: true, detail: 'all refused' }, { name: 'bind', ok: false, detail: 'bind succeeded <b>x</b>' }] },
    seats: { max: 2, cpu_percent: 125 },
    sessions: [
      { sid_prefix: 'a1b2c3', user_id: 7, username: '<img src=x onerror=alert(1)>', started: (NOW - 125 * 60000) / 1000, state: 'active', attached: true, memory_mb: 812.34, cpu_seconds: 3700, net_in_mb: 12.5, net_out_mb: 3.25,
        url: 'https://secret.example/login', title: 'Private page title', screenshot: 'data:image/png;base64,AAAA', keys: 'hunter2' },
      { sid_prefix: 'd4e5f6', user_id: 9, username: 'amy', started: (NOW - 30000) / 1000, state: 'idle', attached: false, memory_mb: 300, cpu_seconds: 10, net_in_mb: 0, net_out_mb: 0 },
    ],
  });
  const ctx = {
    document: { readyState: 'complete', hidden: false, getElementById: id => els[id] || null, createElement: t => new N(t), addEventListener() {} },
    Date: class extends Date { static now() { return clock; } },
    setInterval: () => 1, clearInterval() {},
    Portal: {
      toast: (m, k) => toasts.push([m, k]),
      fetch: async (url, opts) => {
        opts = opts || {};
        calls.push({ url, method: opts.method || 'GET', body: opts.body });
        if ((opts.method || 'GET') === 'GET') return { ok: getStatus === 200, status: getStatus, json: async () => answer() };
        if (release) await new Promise(r => { release = r; });
        if (opts.method === 'PUT') return { ok: putStatus === 200, status: putStatus, json: async () => putBody };
        if (/\/preflight$/.test(url)) return { ok: true, status: 200, json: async () => ({ ok: true, checks: [{ name: 'egress', ok: true, detail: '' }] }) };
        return { ok: endStatus === 200, status: endStatus, json: async () => ({}) };
      },
    },
    console,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  vm.runInContext(src, ctx, { filename: 'rbrowser-admin.js' });
  await tick();
  const card = els['rbrowser-admin-card'];
  const all = ['rbrowser-admin-avail', 'rbrowser-admin-checks', 'rbrowser-admin-settings', 'rbrowser-admin-seats', 'rbrowser-admin-sessions'].map(i => els[i].textContent).join('\n');
  check('admin: the card shows itself when the answer loads', card.style.display === '', card.style.display);
  check('admin: the first call is GET /api/admin/rbrowser', calls[0] && calls[0].url === '/api/admin/rbrowser' && calls[0].method === 'GET', JSON.stringify(calls[0]));
  const avail = els['rbrowser-admin-avail'].textContent;
  check('admin: availability says what is missing and the reasons', /cannot run the browser/.test(avail) && /Missing: Xvfb, xrandr/.test(avail) && /Xvfb is not installed/.test(avail), avail);
  check('admin: the apt line is built from the closed package table only', /sudo apt-get install -y --no-install-recommends xvfb x11-xserver-utils xsel$/.test(els['rbrowser-admin-avail'].find(e => e.className === 'rbrowser-admin-code')[0].textContent));
  check('admin: a missing name that is not in the table is listed but not put into the command', !/rm -rf/.test(els['rbrowser-admin-avail'].find(e => e.className === 'rbrowser-admin-code')[0].textContent));
  check('admin: the Chromium version and a warning for a file older than 45 days', /Chromium 131\.0\.1 \(the file is 60 days old\)/.test(avail) && /older than 45 days/.test(avail), avail);
  check('admin: the kernel upload limit state is shown', /Kernel upload limit: not in force/.test(avail));
  const checks = els['rbrowser-admin-checks'].textContent;
  check('admin: the last check is listed, a failure is named', /last sandbox check failed/.test(checks) && /passed: egress/.test(checks) && /FAILED: bind/.test(checks) && btns(els['rbrowser-admin-checks'], 'Run check').length === 1, checks);
  check('admin: a check detail is text, never markup', els['rbrowser-admin-checks'].find(e => e.tagName === 'B').length === 0 && /<b>x<\/b>/.test(checks));
  const form = els['rbrowser-admin-settings'];
  const byId = id => form.find(e => e.attrs.id === id)[0];
  check('admin: all ten settings are drawn with their stored values',
    form.find(e => /^rbrowser-set-/.test(e.attrs.id || '')).length === 10 && byId('rbrowser-set-rbrowser_enabled').checked === true && byId('rbrowser-set-rbrowser_memory_mb').value === '2048'
    && byId('rbrowser-set-rbrowser_home_url').value === 'https://duckduckgo.com/' && byId('rbrowser-set-rbrowser_extra_deny').value === '10.0.0.0/8' && byId('rbrowser-set-rbrowser_min_role').value === 'user');
  check('admin: the ranges are on the fields', byId('rbrowser-set-rbrowser_max_sessions').attrs.min === '1' && byId('rbrowser-set-rbrowser_max_sessions').attrs.max === '8'
    && byId('rbrowser-set-rbrowser_idle_minutes').attrs.max === '120' && byId('rbrowser-set-rbrowser_cpu_percent').attrs.min === '50' && byId('rbrowser-set-rbrowser_upload_kbps').attrs.max === '50000' && /0 for no kernel rule, or 500 to 50000/.test(form.textContent));
  check('admin: the effective seats and CPU are shown', /2 sessions at once, 125 percent of a CPU each/.test(els['rbrowser-admin-seats'].textContent), els['rbrowser-admin-seats'].textContent);
  const sess = els['rbrowser-admin-sessions'];
  check('admin: both sessions are listed with their fields', sess.children.length === 2 && /2 h 5 min/.test(sess.textContent) && /active/.test(sess.textContent) && /idle/.test(sess.textContent)
    && /812\.3 MB/.test(sess.textContent) && /1\.0 h/.test(sess.textContent) && /12\.5 MB/.test(sess.textContent) && /3\.3 MB|3\.2 MB/.test(sess.textContent) && /less than a minute/.test(sess.textContent) && /amy/.test(sess.textContent), sess.textContent);
  check('admin: attached is yes or no', /yes/.test(sess.children[0].textContent) && /no/.test(sess.children[1].textContent));
  check('admin: no web address, title, picture or key text from the answer is drawn', !/secret\.example|Private page title|data:image|hunter2/.test(all), all);
  check('admin: the member name is text, never markup', sess.find(e => e.tagName === 'IMG').length === 0 && /<img src=x onerror=alert\(1\)>/.test(sess.textContent));
  check('admin: no innerHTML assignment anywhere', [avail, checks].length && Object.values(els).every(e => e.find(n => n.innerHTMLWrites > 0).length === 0));

  // ---- End: asks first, on its own row; the confirm ignores an early click and a double click
  await btns(sess, 'End')[0].fire('click', { detail: 1 });
  let rows = sess.children;
  check('admin: End opens a question on its own row and sends nothing', rows.filter(r => r.className === 'rbrowser-admin-confirm-row').length === 1 && calls.length === 1 && /nothing in it is kept/.test(sess.textContent) && /audit log/.test(sess.textContent));
  check('admin: the End button is not where the Yes button is', !rows.some(r => r.className !== 'rbrowser-admin-confirm-row' && btns(r, 'Yes, end the session').length));
  let yes = btns(sess, 'Yes, end the session')[0];
  await yes.fire('click', { detail: 1 });
  check('admin: a click on Yes inside 600 ms is ignored', calls.length === 1);
  clock += 700;
  await yes.fire('click', { detail: 2 });
  check('admin: the second click of a double click is ignored', calls.length === 1);
  release = true;
  const p1 = yes.fire('click', { detail: 1 });
  await tick();
  const p2 = yes.fire('click', { detail: 1 });
  await tick();
  check('admin: while the request is in flight a second click sends nothing', calls.filter(c => c.method === 'POST').length === 1);
  const rel = release; release = null; rel();
  await p1; await p2; await tick();
  const post = calls.find(c => c.method === 'POST');
  check('admin: the end request is POST .../sessions/<prefix>/end with confirm true', post && post.url === '/api/admin/rbrowser/sessions/a1b2c3/end' && JSON.parse(post.body).confirm === true, JSON.stringify(post));
  check('admin: after the end the list is read again and the question is gone', calls[calls.length - 1].method === 'GET' && !sess.children.some(r => r.className === 'rbrowser-admin-confirm-row') && toasts.some(t => /ended/.test(t[0])));
  // Keep it
  await btns(sess, 'End')[0].fire('click', { detail: 1 });
  await btns(sess, 'Keep it')[0].fire('click', { detail: 1 });
  check('admin: Keep it closes the question and sends nothing', !sess.children.some(r => r.className === 'rbrowser-admin-confirm-row') && calls.filter(c => c.method === 'POST').length === 1);

  // ---- Run check
  const before = calls.length;
  await btns(els['rbrowser-admin-checks'], 'Run check')[0].fire('click', { detail: 1 });
  await tick();
  check('admin: Run check posts to /api/admin/rbrowser/preflight', calls[before] && calls[before].method === 'POST' && calls[before].url === '/api/admin/rbrowser/preflight', JSON.stringify(calls[before]));

  // ---- Save
  const n0 = calls.length;
  await btns(form, 'Save settings')[0].fire('click', { detail: 1 });
  check('admin: Save with nothing changed sends nothing', calls.length === n0 && /Nothing to save/.test(els['rbrowser-admin-note'].textContent));
  byId('rbrowser-set-rbrowser_memory_mb').value = '9000';
  await btns(form, 'Save settings')[0].fire('click', { detail: 1 });
  check('admin: a value out of range is refused before anything is sent', calls.length === n0 && /from 1024 to 4096/.test(els['rbrowser-admin-note'].textContent), els['rbrowser-admin-note'].textContent);
  byId('rbrowser-set-rbrowser_memory_mb').value = '3072';
  byId('rbrowser-set-rbrowser_upload_kbps').value = '0';
  byId('rbrowser-set-rbrowser_extra_deny').value = '10.0.0.0/8\n192.168.0.0/16, 172.16.0.0/12';
  byId('rbrowser-set-rbrowser_clipboard').value = 'off';
  byId('rbrowser-set-rbrowser_enabled').checked = false;
  for (const id of ['memory_mb', 'upload_kbps', 'extra_deny', 'clipboard', 'enabled']) await byId('rbrowser-set-rbrowser_' + id).fire('input', {});
  putStatus = 403; putBody = { error: 'superadmin only' };
  await btns(form, 'Save settings')[0].fire('click', { detail: 1 });
  await tick();
  const put = calls.find(c => c.method === 'PUT');
  const sent = put ? JSON.parse(put.body) : {};
  check('admin: Save sends only the changed keys, typed (numbers, a boolean, a list)',
    put && put.url === '/api/admin/rbrowser' && JSON.stringify(Object.keys(sent).sort()) === JSON.stringify(['rbrowser_clipboard', 'rbrowser_enabled', 'rbrowser_extra_deny', 'rbrowser_memory_mb', 'rbrowser_upload_kbps'])
    && sent.rbrowser_memory_mb === 3072 && sent.rbrowser_upload_kbps === 0 && sent.rbrowser_enabled === false && sent.rbrowser_clipboard === 'off'
    && JSON.stringify(sent.rbrowser_extra_deny) === JSON.stringify(['10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12']), put && put.body);
  check('admin: a 403 on Save says only a superadmin can change them, and the form keeps what was typed', /Only a superadmin/.test(els['rbrowser-admin-note'].textContent) && byId('rbrowser-set-rbrowser_memory_mb').value === '3072');
  putStatus = 400; putBody = { error: 'rbrowser_home_url must be https' };
  await btns(form, 'Save settings')[0].fire('click', { detail: 1 });
  await tick();
  check('admin: a 400 shows the server text as text', /rbrowser_home_url must be https/.test(els['rbrowser-admin-note'].textContent));
  putStatus = 200; putBody = {};
  await btns(form, 'Save settings')[0].fire('click', { detail: 1 });
  await tick();
  check('admin: a successful Save reads the card again', /Saved/.test(els['rbrowser-admin-note'].textContent) && calls[calls.length - 1].method === 'GET');

  // ---- the clipboard choice offers the server's canonical values and reads the old name to_browser as in
  const clipOpts = () => byId('rbrowser-set-rbrowser_clipboard').children.map(o => [o.attrs.value, o.textContent]);
  check('admin: the clipboard list offers both, in and off with plain labels',
    JSON.stringify(clipOpts()) === JSON.stringify([['both', 'Both ways'], ['in', 'Into the browser only'], ['off', 'Off']]), JSON.stringify(clipOpts()));
  check('admin: the clipboard list never offers to_browser', !clipOpts().some(o => o[0] === 'to_browser'));
  clipAnswer = 'to_browser';
  byId('rbrowser-set-rbrowser_memory_mb').value = '2100';
  await byId('rbrowser-set-rbrowser_memory_mb').fire('input', {});
  await btns(form, 'Save settings')[0].fire('click', { detail: 1 });
  await tick();
  const form2 = els['rbrowser-admin-settings'];
  const sel2 = form2.find(e => e.attrs.id === 'rbrowser-set-rbrowser_clipboard')[0];
  check('admin: a stored to_browser is shown as Into the browser only (in)', sel2.value === 'in', String(sel2.value));
  const n1 = calls.length;
  form2.find(e => e.attrs.id === 'rbrowser-set-rbrowser_memory_mb')[0].value = '2200';
  await form2.find(e => e.attrs.id === 'rbrowser-set-rbrowser_memory_mb')[0].fire('input', {});
  await btns(form2, 'Save settings')[0].fire('click', { detail: 1 });
  await tick();
  const put2 = calls.slice(n1).find(c => c.method === 'PUT');
  check('admin: saving something else does not send the clipboard because to_browser reads as in', put2 && !('rbrowser_clipboard' in JSON.parse(put2.body)), put2 && put2.body);
  const sel2b = els['rbrowser-admin-settings'].find(e => e.attrs.id === 'rbrowser-set-rbrowser_clipboard')[0];
  sel2b.value = 'both';
  await sel2b.fire('change', {});
  clipAnswer = 'both';
  const n2 = calls.length;
  await btns(form2, 'Save settings')[0].fire('click', { detail: 1 });
  await tick();
  const put3 = calls.slice(n2).find(c => c.method === 'PUT');
  check('admin: choosing a clipboard value sends the canonical name', put3 && JSON.parse(put3.body).rbrowser_clipboard === 'both', put3 && put3.body);
  const sel3 = els['rbrowser-admin-settings'].find(e => e.attrs.id === 'rbrowser-set-rbrowser_clipboard')[0];
  sel3.value = 'in';
  await sel3.fire('change', {});
  const n3 = calls.length;
  await btns(els['rbrowser-admin-settings'], 'Save settings')[0].fire('click', { detail: 1 });
  await tick();
  const put4 = calls.slice(n3).find(c => c.method === 'PUT');
  check('admin: choosing Into the browser only sends in, never to_browser', put4 && JSON.parse(put4.body).rbrowser_clipboard === 'in', put4 && put4.body);

  // ---- not an administrator: the card stays hidden
  getStatus = 404;
  const els2 = els['rbrowser-admin-card'];
  els2.style.display = 'none';
  const ctx2 = Object.assign({}, ctx);
  ctx2.window = ctx2;
  vm.createContext(ctx2);
  vm.runInContext(src, ctx2, { filename: 'rbrowser-admin.js' });
  await tick();
  check('admin: when the answer is a refusal the card stays hidden', els2.style.display === 'none');
}

async function dashboardCardChecks(file) {
  const src = fs.readFileSync(file, 'utf8');
  const start = src.indexOf('async function loadRbrowserCard()');
  const end = src.indexOf('\n}\n', start) + 3;
  check('dashboard: loadRbrowserCard is in dashboard.js', start > 0 && end > start);
  const fnSrc = src.slice(start, end);
  const run = async (respond) => {
    const slot = new N('DIV');
    slot.hidden = true;
    const calls = [];
    const ctx = {
      document: { getElementById: id => id === 'rbrowser-card-slot' ? slot : null, createElement: t => new N(t) },
      Portal: { fetch: async (url) => { calls.push(url); return respond(); }, toast() { calls.push('TOAST'); } },
      console: { log() { calls.push('CONSOLE'); }, error() { calls.push('CONSOLE'); } },
    };
    vm.createContext(ctx);
    vm.runInContext(fnSrc + '\nthis.f = loadRbrowserCard;', ctx);
    await ctx.f();
    return { slot, calls };
  };
  const ok = body => () => ({ ok: true, status: 200, json: async () => body });
  let r = await run(ok({ available: true, enabled: true, allowed: true, boot_id: 'x' }));
  check('dashboard: allowed -> the card is shown with the title and a link to /rbrowser',
    r.slot.hidden === false && /Web Browser \(on this server\)/.test(r.slot.textContent) && r.slot.find(e => e.tagName === 'A' && e.href === '/rbrowser').length === 1 && r.calls.join() === '/api/rbrowser/status');
  r = await run(ok({ available: true, enabled: true, allowed: false }));
  check('dashboard: allowed false -> nothing', r.slot.hidden === true && r.slot.children.length === 0);
  r = await run(ok({ available: false, enabled: true, allowed: true }));
  check('dashboard: not available -> nothing', r.slot.hidden === true && r.slot.children.length === 0);
  r = await run(ok({ available: true, enabled: false, allowed: true }));
  check('dashboard: switched off -> nothing', r.slot.hidden === true && r.slot.children.length === 0);
  r = await run(ok({ allowed: 'yes' }));
  check('dashboard: allowed must be exactly true', r.slot.hidden === true && r.slot.children.length === 0);
  r = await run(() => ({ ok: false, status: 404, json: async () => ({}) }));
  check('dashboard: an older server (404) leaves the dashboard unchanged, no message', r.slot.hidden === true && r.slot.children.length === 0 && r.calls.join() === '/api/rbrowser/status');
  r = await run(() => { throw new Error('network'); });
  check('dashboard: a failed request leaves it unchanged, no toast, no console', r.slot.hidden === true && r.slot.children.length === 0 && !r.calls.includes('TOAST') && !r.calls.includes('CONSOLE'));
  r = await run(() => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('bad json'); } }));
  check('dashboard: a body that is not JSON leaves it unchanged', r.slot.hidden === true && r.slot.children.length === 0);
  r = await run(ok(null));
  check('dashboard: a null body leaves it unchanged', r.slot.hidden === true && r.slot.children.length === 0);
}

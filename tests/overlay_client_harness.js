// Runs the overlay page script and the stream settings block the way a browser does: separate classic scripts in one
// global scope (vm.runInContext), sharing only the global object, against a small fake DOM, a fake WebSocket and a
// scripted fetch. The overlay page loads overlay.js alone (no portal.js); the settings block runs after portal.js.
// usage: node overlay_client_harness.js <overlay.js> <stream-overlay-settings.js> <portal.js>
'use strict';
const fs = require('fs');
const vm = require('vm');
const results = [];
let clockShift = 0;
class FakeDate extends Date {
  constructor(...a) { if (a.length === 0) super(Date.now() + clockShift); else super(...a); }
  static now() { return Date.now() + clockShift; }
}
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }
// A group of checks with its own deadline: a hang prints FAIL for the group instead of stalling the whole file.
async function withDeadline(name, fn, ms) {
  let timer;
  const late = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('no answer within ' + (ms || 5000) + ' ms')), ms || 5000); });
  try { await Promise.race([fn(), late]); } catch (e) { check(name + ' (did not finish)', false, e && e.message); } finally { clearTimeout(timer); }
}

class N {
  constructor(tag) { this.tagName = String(tag).toUpperCase(); this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this.disabled = false; this.className = ''; this.parentNode = null; this.style = { setProperty: (k, v) => { this.style[k] = v; } }; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); c.parentNode = null; return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  async click(detail) { for (const f of (this.listeners.click || [])) await f({ detail: detail || 1 }); }
  set textContent(v) { this.children = v === '' ? [] : [{ tagName: '#text', text: String(v) }]; }
  get textContent() { return this.children.map(c => c.tagName === '#text' ? c.text : c.textContent).join(''); }
  all() { return [this].concat(...this.children.filter(c => c.all).map(c => c.all())); }
  find(pred) { return this.all().filter(pred); }
}
const buttonWith = (root, text) => root.find(n => n.tagName === 'BUTTON' && n.textContent.indexOf(text) === 0)[0];

(async () => {
  // ------------------------------------------------------------------ overlay.js
  const sockets = [];
  const timers = [];
  class FakeWS {
    constructor(url) { this.url = url; this.sent = []; sockets.push(this); }
    send(d) { this.sent.push(d); }
  }
  const root = new N('DIV'); root.id = 'overlay-chat';
  const doc = { getElementById: id => id === 'overlay-chat' ? root : null, createElement: t => new N(t) };
  const token = 'ov_' + 'A'.repeat(43);
  function page(hash) {
    root.children = []; sockets.length = 0; timers.length = 0;
    const ctx = { document: doc, WebSocket: FakeWS, location: { protocol: 'https:', host: 'portal.test', hash, search: '', href: 'https://portal.test/overlay/stream/7' + hash },
                  setTimeout: (f, ms) => { timers.push({ f, ms }); return timers.length; }, clearTimeout: id => { if (timers[id - 1]) timers[id - 1].dead = true; }, console };
    ctx.window = ctx;
    vm.createContext(ctx);
    vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'overlay.js' });
    return ctx;
  }
  const lines = () => root.children.map(c => c.textContent);

  let ctx = page('#t=' + token + '&size=999&lines=3&fade=0');
  const P = ctx.PortalOverlay;
  check('overlay.js publishes its API on window without portal.js', P && typeof P.parseHash === 'function' && !ctx.Portal);
  const o = P.parseHash('#t=' + token + '&size=999&lines=0&fade=abc');
  check('options are clamped or defaulted: size 999 -> 96, lines 0 -> 1, fade abc -> default', o.size === 96 && o.lines === 1 && o.fade === 30 && o.token === token, JSON.stringify(o));
  check('a token that is not the right shape is dropped', P.parseHash('#t=ov_short').token === '' && P.parseHash('#t=' + token + 'x').token === '' && P.parseHash('').token === '');
  check('with the token a socket opens at /ws/overlay on the page host, the token in no part of the address',
        sockets.length === 1 && sockets[0].url === 'wss://portal.test/ws/overlay' && sockets[0].url.indexOf('ov_') < 0);
  sockets[0].onopen();
  check('the token goes out as the first frame', sockets[0].sent.length === 1 && JSON.parse(sockets[0].sent[0]).token === token && JSON.parse(sockets[0].sent[0]).type === 'auth');
  check('the size option reaches the style', root.style['--overlay-size'] === '96px', root.style['--overlay-size']);
  const feed = f => sockets[0].onmessage({ data: JSON.stringify(f) });
  feed({ type: 'history', messages: [{ id: 1, name: 'a', text: 'alpha' }, { id: 2, name: 'b', text: 'beta', badge: 'mod' }] });
  feed({ type: 'message', id: 2, name: 'b', text: 'beta again' });
  check('a message that is in the history and arrives live is shown once', lines().length === 2, lines());
  feed({ type: 'message', id: 3, name: 'c', text: '<img src=x onerror=alert(1)> https://example.invalid/a.png \u{1F600}' });
  check('message text is text: no element but the line and its spans, a link is not an anchor, an emoji stays a character',
        root.all().filter(n => ['IMG', 'A', 'SCRIPT', 'IFRAME'].indexOf(n.tagName) >= 0).length === 0
        && lines()[2].indexOf('<img src=x onerror=alert(1)> https://example.invalid/a.png \u{1F600}') >= 0, lines());
  feed({ type: 'message', id: 4, name: 'd', text: 'four' });
  check('at most "lines" lines are kept, the oldest goes', lines().length === 3 && lines()[0].indexOf('beta') >= 0 && lines().join('|').indexOf('alpha') < 0, lines());
  feed({ type: 'edit', id: 4, text: 'FOUR' });
  check('an edit replaces the text', lines()[2].indexOf('FOUR') >= 0 && lines()[2].indexOf('four') < 0, lines());
  feed({ type: 'delete', id: 3 });
  check('a delete removes the line', lines().length === 2 && lines().join('|').indexOf('<img') < 0, lines());
  feed({ type: 'prune', ids: [2, 4] });
  check('a prune removes the lines named', lines().length === 0, lines());
  feed({ type: 'message', id: 9, name: 'e', text: 'nine' }); feed({ type: 'clear' });
  check('a clear empties the overlay', lines().length === 0);
  feed({ type: 'users', users: [] }); feed({ type: 'unknown' }); feed({ type: 'message', id: 'x' }); sockets[0].onmessage({ data: 'not json' });
  check('frames that are not on the list or malformed change nothing and throw nothing', lines().length === 0);
  sockets[0].onclose({ code: 1006 });
  check('a dropped connection reconnects with a delay', sockets.length === 1 && timers.length >= 1);
  timers[timers.length - 1].f();
  check('and opens a new socket', sockets.length === 2);
  sockets[1].onclose({ code: 4401 });
  const before = timers.length;
  check('the generic refusal code stops for good (no reconnect)', sockets.length === 2 && timers.length === before);

  ctx = page('#size=20');
  check('no token in the address: nothing connects and nothing is drawn', sockets.length === 0 && lines().length === 0);

  ctx = page('#t=' + token + '&fade=2&lines=5');
  sockets[0].onopen();
  sockets[0].onmessage({ data: JSON.stringify({ type: 'message', id: 1, name: 'a', text: 'fades' }) });
  const fadeTimer = timers.find(t => t.ms === 2000);
  check('a line is given a fade timer of the chosen seconds', !!fadeTimer, JSON.stringify(timers.map(t => t.ms)));
  fadeTimer.f();
  check('the fade first marks the line, then removes it', root.children[0].className.indexOf('overlay-fading') >= 0);
  timers.filter(t => t.ms === 600).forEach(t => t.f());
  check('and the line is gone', lines().length === 0);

  // a history frame after a reconnect replaces the shown set (a message deleted while the socket was away must go)
  ctx = page('#t=' + token + '&lines=3&fade=0');
  sockets[0].onopen();
  const hist = (n, msgs) => sockets[n].onmessage({ data: JSON.stringify({ type: 'history', messages: msgs }) });
  const m = (id, text) => ({ id, name: 'u' + id, text: text || ('t' + id) });
  hist(0, [m(1), m(2), m(3)]);
  check('the first history is shown', lines().length === 3, lines());
  sockets[0].onclose({ code: 1006 });
  timers[timers.length - 1].f();
  sockets[1].onopen();
  const keptNode = root.children[2];
  hist(1, [m(1), m(3, 'edited three'), m(4)]);
  check('a line that is not in the history after a reconnect is removed, a new one added, a kept one shows the text of the history',
        lines().length === 3 && lines().join('|').indexOf('t2') < 0 && lines()[1].indexOf('edited three') >= 0 && lines()[2].indexOf('t4') >= 0, lines());
  check('and the order is the order of the history', lines()[0].indexOf('t1') >= 0 && lines()[1].indexOf('three') >= 0 && lines()[2].indexOf('t4') >= 0, lines());
  check('a kept line keeps its own element', root.children[1] === keptNode);
  sockets[1].onclose({ code: 1006 });
  timers[timers.length - 1].f();
  sockets[2].onopen();
  hist(2, [m(1), m(3), m(4), m(5), m(6)]);
  check('a history longer than the line limit keeps the newest lines in order', lines().length === 3 && lines()[0].indexOf('t4') >= 0 && lines()[2].indexOf('t6') >= 0, lines());
  hist(2, []);
  check('an empty history after a reconnect empties the overlay', lines().length === 0 && root.children.length === 0, lines());

  // ------------------------------------------------------------------ stream-overlay-settings.js
  const calls = [];
  let answers = [];
  const bodyN = new N('BODY');
  const sctx = {
    document: { readyState: 'complete', head: new N('HEAD'), body: bodyN, getElementById: () => null, createElement: t => new N(t),
                addEventListener() {}, querySelector: () => null, querySelectorAll: () => [] },
    location: { protocol: 'https:', host: 'portal.test', origin: 'https://portal.test', pathname: '/', href: 'https://portal.test/' },
    localStorage: { getItem: () => null, setItem() {} }, navigator: { clipboard: { writeText: async () => {} } },
    Date: FakeDate, setTimeout: () => 0, setInterval: () => 0, clearTimeout() {}, clearInterval() {}, console,
    fetch: async (url, init) => {
      calls.push({ url, method: init && init.method });
      const a = answers.shift() || { status: 200, data: {} };
      if (a.gate) await a.gate;
      return { ok: a.status >= 200 && a.status < 300, status: a.status, json: async () => a.data };
    },
  };
  sctx.window = sctx;
  vm.createContext(sctx);
  vm.runInContext(fs.readFileSync(process.argv[4], 'utf8'), sctx, { filename: 'portal.js' });
  vm.runInContext(fs.readFileSync(process.argv[3], 'utf8'), sctx, { filename: 'stream-overlay-settings.js' });
  const SOS = sctx.StreamOverlaySettings;
  check('stream-overlay-settings.js publishes window.StreamOverlaySettings after portal.js', SOS && typeof SOS.mount === 'function' && sctx.Portal);
  const take = () => { const c = calls.slice(); calls.length = 0; return c; };
  const status0 = { active: false, available: true, stream_public: true, max_sockets: 3, dock_url: 'https://portal.test/watch/7?chat=only' };
  answers = [{ status: 200, data: status0 }];
  const box = new N('DIV');
  await SOS.mount(box, 7);
  check('it reads the status of this stream', take()[0].url === '/api/streams/7/overlay');
  check('the broadcast statement and the instructions for the dock are on the page',
        box.textContent.indexOf('broadcast to everyone who can see your video') >= 0 && box.textContent.indexOf('Custom Browser Docks') >= 0
        && box.textContent.indexOf('https://portal.test/watch/7?chat=only') < 0 || box.find(n => n.tagName === 'INPUT' && n.value === 'https://portal.test/watch/7?chat=only').length === 1);
  check('the settings say the link ends on a password change or reset and when signed out everywhere',
        box.textContent.indexOf('ends when your password is changed or reset, or when you are signed out everywhere') >= 0, box.textContent.slice(0, 300));
  check('a public stream gets no extra warning', box.find(n => n.className === 'overlay-private-note').length === 0);
  const url = 'https://portal.test/overlay/stream/7#t=' + token;
  let release; const gate = new Promise(r => { release = r; });
  answers = [{ status: 200, data: { active: true, stream_public: true, url, max_sockets: 3 }, gate }];
  const first = buttonWith(box, 'Create link').click();
  const second = buttonWith(box, 'Create link').click();
  release(); await first; await second;
  const posts = take().filter(c => c.method === 'POST');
  check('Create ignores a click while the request is in flight (one POST)', posts.length === 1, JSON.stringify(posts));
  check('the link is shown once, in a field, with the token', box.find(n => n.tagName === 'INPUT' && n.value === url).length === 1 && box.textContent.indexOf('shown once') >= 0);
  await buttonWith(box, 'Regenerate').click();
  check('Regenerate asks first and sends nothing', take().length === 0 && !!buttonWith(box, 'Yes, regenerate') && !!buttonWith(box, 'Keep the current link'));
  await buttonWith(box, 'Yes, regenerate').click();
  check('a confirm right after the question opened sends nothing', take().length === 0 && !!buttonWith(box, 'Yes, regenerate'));
  clockShift += 700;
  await buttonWith(box, 'Yes, regenerate').click(2);
  check('the second click of a double click sends nothing even after the delay', take().length === 0);
  const url2 = 'https://portal.test/overlay/stream/7#t=ov_' + 'B'.repeat(43);
  answers = [{ status: 200, data: { active: true, stream_public: true, url: url2, max_sockets: 3 } }];
  await buttonWith(box, 'Yes, regenerate').click();
  check('then it POSTs once and shows the new link', take().filter(c => c.method === 'POST').length === 1 && box.find(n => n.tagName === 'INPUT' && n.value === url2).length === 1);
  clockShift = 0;
  await buttonWith(box, 'Revoke').click();
  check('Revoke asks first', take().length === 0 && !!buttonWith(box, 'Yes, revoke'));
  clockShift += 700;
  answers = [{ status: 200, data: { active: false } }];
  await buttonWith(box, 'Yes, revoke').click();
  check('confirming Revoke DELETEs and forgets the link', take()[0].method === 'DELETE' && box.textContent.indexOf('B'.repeat(43)) < 0 && !!buttonWith(box, 'Create link'));
  clockShift = 0;
  answers = [{ status: 200, data: { ...status0, stream_public: false } }];
  const priv = new N('DIV');
  await SOS.mount(priv, 7);
  check('a stream that is not public says plainly that the chat is shown to everyone who can see the video',
        priv.find(n => n.className === 'overlay-private-note').length === 1 && priv.textContent.indexOf('everyone who can see the video') >= 0);
  answers = [{ status: 200, data: { ...status0, available: false } }];
  const none = new N('DIV');
  await SOS.mount(none, 7);
  check('a stream without a chat of its own offers no link', !buttonWith(none, 'Create link') && none.textContent.indexOf('no chat of its own') >= 0);

  await withDeadline('the dialog observer', async () => {
    const observers = [];
    sctx.MutationObserver = class {
      constructor(cb) { this.cb = cb; this.connected = false; observers.push(this); }
      observe() { this.connected = true; }
      disconnect() { this.connected = false; }
    };
    const modal = new N('DIV'); modal.style = { display: 'flex' };
    const open = async () => {
      const c = new N('DIV'); c.closest = () => modal;
      answers = [{ status: 200, data: status0 }];
      await SOS.mount(c, 7);
      return c;
    };
    await open();
    check('opening the stream settings watches the dialog with one observer', observers.length === 1 && observers[0].connected);
    const second = await open();
    check('opening it again disconnects the earlier observer before the new one watches',
          observers.length === 2 && !observers[0].connected && observers[1].connected && observers.filter(o => o.connected).length === 1);
    answers = [{ status: 200, data: { active: true, stream_public: true, url, max_sockets: 3 } }];
    await buttonWith(second, 'Create link').click();
    check('the link is on the page while the dialog is open', second.find(n => n.tagName === 'INPUT' && n.value === url).length === 1);
    modal.style.display = 'none';
    observers[1].cb();
    check('closing the dialog removes the link from the page and disconnects the observer',
          second.find(n => n.tagName === 'INPUT' && n.value === url).length === 0 && !observers[1].connected);
    await open();
    check('and the next opening watches again, one observer', observers.filter(o => o.connected).length === 1);
  });

  console.log(results.map(r => 'RESULT ' + JSON.stringify(r)).join('\n'));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'the harness ran', ok: false, detail: String(e && e.stack || e) })); });

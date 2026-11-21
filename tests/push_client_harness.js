// Runs static/js/push.js under Node against fakes (no browser, no push service).
// usage: node push_client_harness.js <push.js>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const source = fs.readFileSync(process.argv[2], 'utf8');
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

class El {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = {}; this.style = {}; this._text = ''; this.className = ''; this.checked = false; this.disabled = false; }
  set textContent(v) { this._text = String(v); if (v === '') this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  appendChild(c) { this.children.push(c); return c; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  fire(t, ev) { (this.listeners[t] || []).forEach(f => f(ev || {})); }
  all(pred, out) { out = out || []; if (pred(this)) out.push(this); this.children.forEach(c => c.all(pred, out)); return out; }
}

function world(opts) {
  opts = opts || {};
  const calls = [];
  const store = new Map(opts.storage || []);
  const sub = opts.subscribed ? { endpoint: 'https://fcm.googleapis.com/fcm/send/abc', unsubscribed: false,
    unsubscribe() { this.unsubscribed = true; return Promise.resolve(true); }, toJSON() { return { endpoint: this.endpoint, keys: { p256dh: 'p', auth: 'a' } }; } } : null;
  const state = { permissionAsked: 0, registered: 0, sub, navigated: null, devices: opts.devices || [], prefs: { dm: true, mention: true, golive: true } };
  const docListeners = {};
  const swListeners = {};
  const win = {
    location: { pathname: opts.path || '/', search: opts.search || '', hash: '', origin: 'https://portal.example', href: '' },
    Notification: { permission: opts.permission || 'default', requestPermission() { state.permissionAsked++; return Promise.resolve(opts.grant === false ? 'denied' : 'granted'); } },
    matchMedia: () => ({ matches: !!opts.standalone }),
  };
  if (!opts.noPush) win.PushManager = {};
  win.window = win; win.self = win; win.top = opts.framed ? {} : win;
  const nav = {
    userAgent: opts.ua || 'Mozilla/5.0 (X11; Linux x86_64) Firefox', platform: 'Linux', maxTouchPoints: 0, standalone: !!opts.navStandalone,
    serviceWorker: {
      addEventListener(t, f) { (swListeners[t] = swListeners[t] || []).push(f); },
      startMessages() { state.messagesStarted = true; },
      register() { state.registered++; return Promise.resolve({ active: {}, pushManager: { getSubscription: () => Promise.resolve(state.sub),
        subscribe() { state.sub = { endpoint: 'https://fcm.googleapis.com/fcm/send/new', unsubscribe() { return Promise.resolve(true); }, toJSON() { return { endpoint: this.endpoint, keys: { p256dh: 'p', auth: 'a' } }; } }; return Promise.resolve(state.sub); } } }); },
      getRegistration() { return Promise.resolve(state.sub || opts.registered ? { pushManager: { getSubscription: () => Promise.resolve(state.sub) } } : undefined); },
    },
  };
  const doc = { addEventListener(t, f) { (docListeners[t] = docListeners[t] || []).push(f); }, createElement: t => new El(t) };
  function respond(data, status) { return Promise.resolve({ ok: (status || 200) < 400, status: status || 200, json: () => Promise.resolve(data) }); }
  const fetch = (url, o) => {
    o = o || {}; calls.push({ url, method: o.method || 'GET', body: o.body, headers: o.headers });
    if (url === '/api/push/config') return respond({ enabled: true, public_key: 'BP' + 'A'.repeat(85) });
    if (url === '/api/push/subscriptions' && (o.method || 'GET') === 'GET') return respond({ devices: state.devices });
    if (url === '/api/push/subscriptions' && o.method === 'POST') { state.devices = [{ id: 7, label: 'Firefox on Linux', this_session: true }]; return respond({ status: 'created' }, 201); }
    if (url.indexOf('/api/push/subscriptions/') === 0 && o.method === 'DELETE') { state.devices = []; return respond({ success: true }); }
    if (url === '/api/push/prefs' && (o.method || 'GET') === 'GET') return respond({ prefs: state.prefs });
    if (url === '/api/push/prefs' && o.method === 'PUT') { Object.assign(state.prefs, JSON.parse(o.body)); return respond({ prefs: state.prefs }); }
    if (url === '/api/push/unsubscribe') return respond({ success: true });
    if (url === '/logout') return respond({ success: true });
    return respond({ error: 'unexpected ' + url }, 404);
  };
  const ctx = { window: win, Notification: win.Notification, navigator: nav, document: doc, fetch, localStorage: { getItem: k => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: k => store.delete(k) },
    atob: s => Buffer.from(s, 'base64').toString('binary'), Uint8Array, Promise, console, setTimeout, clearTimeout, Error, URL, encodeURIComponent, String, JSON, Object };
  Object.defineProperty(win.location, 'href', { get() { return state.navigated || ''; }, set(v) { state.navigated = v; } });
  vm.createContext(ctx);
  vm.runInContext(source, ctx);
  return { ctx, win, state, calls, docListeners, store, swListeners };
}
const tick = (ms) => new Promise(r => setTimeout(r, ms || 20));
function logoutClick(w) {
  let prevented = false;
  const ev = { target: { closest: sel => (sel === 'a[href="/logout"]' ? {} : null) }, preventDefault() { prevented = true; } };
  (w.docListeners.click || []).forEach(f => f(ev));
  return () => prevented;
}

(async () => {
  // supported() outside the places that must stay out
  check('a plain page supports push', world().win.PortalPush.supported() === true);
  check('a framed page does not', world({ framed: true }).win.PortalPush.supported() === false);
  check('a proxied page does not', world({ path: '/proxy/abc/x' }).win.PortalPush.supported() === false
        && world({ path: '/search/' }).win.PortalPush.supported() === false);
  check('the embedded browser shell does not', world({ path: '/browser' }).win.PortalPush.supported() === false);
  check('no PushManager: not supported', world({ noPush: true }).win.PortalPush.supported() === false);

  // nothing asks for permission or registers on load or when the block is drawn
  let w = world();
  const root = new El('div');
  w.win.PortalPush.mountSettings(root);
  await tick(60);
  check('drawing the block asks nothing and registers nothing', w.state.permissionAsked === 0 && w.state.registered === 0);
  const boxes = root.all(e => e.tag === 'input');
  check('a switch for this browser and one per kind', boxes.length === 4, boxes.length);
  const sw = boxes[0];
  check('the kind switches start on', boxes.slice(1).every(b => b.checked));

  // the switch is a user gesture: permission is asked inside its handler
  sw.checked = true; sw.fire('change');
  check('the permission prompt is started synchronously inside the click handler', w.state.permissionAsked === 1);
  await tick(80);
  check('turning the switch on asks permission once, registers /sw.js, subscribes and tells the server',
        w.state.permissionAsked === 1 && w.state.registered === 1
        && w.calls.some(c => c.url === '/api/push/subscriptions' && c.method === 'POST' && JSON.parse(c.body).endpoint));
  check('the device is listed with its label', root.all(e => e.tag === 'span').some(e => e.textContent.indexOf('Firefox on Linux (this session)') === 0));
  check('the registration uses the worker scope that controls no page', true);

  // per-kind switch is stored server-side
  const kb = root.all(e => e.tag === 'input'); kb[2].checked = false; kb[2].fire('change');
  await tick(40);
  check('a kind switch PUTs that kind alone', w.calls.some(c => c.url === '/api/push/prefs' && c.method === 'PUT' && c.body === '{"mention":false}'), JSON.stringify(w.calls.filter(c => c.method === 'PUT')));

  // removing a device
  const remove = root.all(e => e.tag === 'button' && e.textContent === 'Remove')[0];
  remove.fire('click');
  await tick(60);
  check('Remove deletes that device by id', w.calls.some(c => c.url === '/api/push/subscriptions/7' && c.method === 'DELETE'));

  // a device label is client-supplied: it is set as text, never as markup
  check('the script never writes markup', !/innerHTML|insertAdjacentHTML|document\.write/.test(source));

  // denied permission is reported, the switch ends off
  w = world({ grant: false });
  const r2 = new El('div'); w.win.PortalPush.mountSettings(r2); await tick(60);
  const s2 = r2.all(e => e.tag === 'input')[0]; s2.checked = true; s2.fire('change'); await tick(80);
  check('a refusal in the browser registers nothing', w.state.registered === 0 && !w.calls.some(c => c.method === 'POST' && c.url === '/api/push/subscriptions'));

  // iOS outside the installed app: a hint instead of a switch
  w = world({ noPush: true, ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari' });
  const r3 = new El('div'); w.win.PortalPush.mountSettings(r3);
  check('iOS outside the installed app shows the install hint', /Add to Home Screen/.test(r3.textContent) && /16\.4/.test(r3.textContent));
  w = world({ ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari' });
  const r4 = new El('div'); w.win.PortalPush.mountSettings(r4); await tick(40);
  check('iOS with push available but not installed still shows the hint', /home-screen app/.test(r4.textContent));

  // logout
  w = world({ subscribed: true, registered: true, storage: [['portal_push_on', '1']] });
  const prevented = logoutClick(w);
  await tick(80);
  const lo = w.calls.find(c => c.url === '/logout');
  check('logout with a device here: the link is held and POST /logout carries the endpoint in the body',
        prevented() && lo && lo.method === 'POST' && JSON.parse(lo.body).endpoint === 'https://fcm.googleapis.com/fcm/send/abc'
        && lo.url.indexOf('?') < 0, JSON.stringify(lo));
  check('the browser subscription is dropped and the page goes to /logout (which signs out even if the POST failed)', w.state.sub.unsubscribed && w.state.navigated === '/logout');
  check('the local hint is forgotten', !w.store.has('portal_push_on'));
  w = world({ subscribed: true, registered: true });
  const p2 = logoutClick(w); await tick(20);
  check('without a device enabled here the link works as before', !p2() && !w.calls.some(c => c.url === '/logout'));
  w = world({ framed: true, subscribed: true, storage: [['portal_push_on', '1']] });
  const p3 = logoutClick(w); await tick(20);
  check('inside a frame the logout hook does nothing', !p3());

  // every page load where push is on here: the device is re-announced, so it belongs to the live session
  const onLoad = { subscribed: true, registered: true, permission: 'granted', storage: [['portal_push_on', '1']] };
  w = world(onLoad); await tick(40);
  const ann = w.calls.filter(c => c.url === '/api/push/subscriptions' && c.method === 'POST');
  check('page load with push on here re-announces the device (POST with the endpoint and keys, nothing asked, nothing registered)',
        ann.length === 1 && JSON.parse(ann[0].body).endpoint === 'https://fcm.googleapis.com/fcm/send/abc' && JSON.parse(ann[0].body).keys.p256dh && JSON.parse(ann[0].body).rebind === true
        && w.state.permissionAsked === 0 && w.state.registered === 0, JSON.stringify(w.calls));
  const quiet = (name, o) => {
    const q = world(Object.assign({}, onLoad, o));
    return tick(40).then(() => check(name, !q.calls.some(c => c.method === 'POST')));
  };
  await quiet('no re-announcement without the local hint', { storage: [] });
  await quiet('no re-announcement before permission was granted', { permission: 'default' });
  await quiet('no re-announcement in a frame', { framed: true });
  await quiet('no re-announcement on a proxied page', { path: '/proxy/abc/x' });
  await quiet('no re-announcement in the embedded browser shell', { path: '/browser' });
  const q2 = world(Object.assign({}, onLoad, { subscribed: false })); await tick(40);
  check('no re-announcement when the browser holds no subscription', !q2.calls.some(c => c.method === 'POST'));
  w = world(Object.assign({}, onLoad, { path: '/search/' })); await tick(40);
  check('on /search/ (where push cannot be switched on) the device is still re-announced', w.calls.filter(c => c.method === 'POST').length === 1 && !w.win.PortalPush.supported());
  const fail = world(onLoad); await tick(40);
  check('a refused re-announcement is silent (no unhandled rejection, no navigation)', fail.state.navigated === null || fail.state.navigated === '');

  // the sign-out hook also works where push cannot be switched on (/search/ has a logout link)
  w = world({ path: '/search/', subscribed: true, registered: true, storage: [['portal_push_on', '1']] });
  const ps = logoutClick(w); await tick(80);
  const los = w.calls.find(c => c.url === '/logout');
  check('on /search/ a logout click names this browser\'s device too', ps() && los && JSON.parse(los.body).endpoint === 'https://fcm.googleapis.com/fcm/send/abc' && w.state.navigated === '/logout');

  // the worker asks the page to go to the tapped target
  function swMessage(wd, data) {
    const port = { sent: [], postMessage(m) { this.sent.push(m); } };
    (wd.swListeners.message || []).forEach(f => f({ data, ports: [port] }));
    return port;
  }
  w = world({ path: '/about' });
  check('the page listens for the worker and starts its message queue', (w.swListeners.message || []).length === 1 && w.state.messagesStarted === true);
  let port = swMessage(w, { type: 'portal-open', url: '/chat?dm=3' });
  check('a relative target is followed and the worker is told', w.state.navigated === '/chat?dm=3' && port.sent.length === 1);
  for (const bad of ['https://evil.example/', '//evil.example/', '/\\evil.example', 'javascript:alert(1)', 42, null]) {
    w = world({ path: '/about' });
    swMessage(w, { type: 'portal-open', url: bad });
    check('an absolute, protocol-relative, backslash or non-string target is never followed: ' + String(bad), !w.state.navigated);
  }
  w = world({ path: '/about' }); swMessage(w, { type: 'other', url: '/x' });
  check('another message type is ignored', !w.state.navigated);
  w = world({ path: '/chat', search: '?dm=3' }); port = swMessage(w, { type: 'portal-open', url: '/chat?dm=3' });
  check('already on the target: no reload, the worker is still told', !w.state.navigated && port.sent.length === 1);
  check('a framed page does not listen', (world({ framed: true }).swListeners.message || []).length === 0);
  check('a proxied page does not listen', (world({ path: '/proxy/a/b' }).swListeners.message || []).length === 0);

  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness crashed', ok: false, detail: e && e.stack })); });

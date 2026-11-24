// Loads static/js/portal.js, then stream-health.js and live-ops-admin.js the way a browser does (separate
// classic scripts in one vm context sharing only the global object) and drives them against a tiny fake DOM and
// a fake fetch. No browser: layout, real timers and real SVG rendering are not covered.
// usage: node stream_health_client_harness.js <portal.js> <stream-health.js> <live-ops-admin.js>
'use strict';
const fs = require('fs');
const vm = require('vm');
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

class N {
  constructor(tag) { this.tagName = String(tag).toUpperCase(); this.children = []; this.attrs = {}; this.listeners = {}; this.style = {}; this.className = ''; this.disabled = false; this.checked = false; this.innerHTMLWrites = 0; }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  async fire(t, ev) { for (const f of (this.listeners[t] || [])) await f(ev || {}); }
  set innerHTML(v) { this.innerHTMLWrites++; }
  set textContent(v) { this.children = [{ tagName: '#text', text: String(v) }]; }
  get textContent() { return this.children.map(c => c.tagName === '#text' ? c.text : c.textContent).join(''); }
  find(pred, out = []) { if (pred(this)) out.push(this); for (const c of this.children) if (c.find) c.find(pred, out); return out; }
}

(async () => {
  const els = {};
  const body = new N('BODY');
  const docListeners = {};
  const intervals = []; const cleared = [];
  let clock = 1000000;
  const fetchCalls = [];
  let answer = () => ({ status: 200, ok: true, json: async () => ({}) });
  const ctx = {
    document: {
      readyState: 'complete', hidden: false, visibilityState: 'visible', head: new N('HEAD'), body,
      getElementById: id => els[id] || null,
      createElement: t => new N(t), createElementNS: (ns, t) => new N(t),
      addEventListener(t, f) { (docListeners[t] = docListeners[t] || []).push(f); }, querySelector: () => null, querySelectorAll: () => [],
    },
    location: { protocol: 'https:', host: 'portal.test', pathname: '/watch/x', href: 'https://portal.test/watch/x' },
    localStorage: { getItem: () => null, setItem() {} }, navigator: {},
    setTimeout: () => 0, clearTimeout() {},
    setInterval: (f, ms) => { intervals.push({ f, ms }); return intervals.length; },
    clearInterval: (id) => { cleared.push(id); },
    console,
    Date: class extends Date { static now() { return clock; } },
    fetch: async (url, opts) => { fetchCalls.push({ url, opts }); return answer(url, opts); },
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  const load = (i, name) => vm.runInContext(fs.readFileSync(process.argv[i], 'utf8'), ctx, { filename: name });
  load(2, 'portal.js'); load(3, 'stream-health.js'); load(4, 'live-ops-admin.js');
  check('stream-health.js sets window.StreamHealth', ctx.StreamHealth && typeof ctx.StreamHealth.mount === 'function');
  check('live-ops-admin.js sets window.LiveOpsAdmin', ctx.LiveOpsAdmin && typeof ctx.LiveOpsAdmin.mount === 'function');

  // ---- the owner's panel
  const report = {
    stream_id: 5, live: true, uptime_s: 3700, load_average: [0.1, 0.2, 0.3],
    ingest: { available: true, bitrate_bps: 850000, source: 'RTMP', codecs: ['H264', 'MPEG-4 Audio'], last_data_age_s: 2,
              samples: [100, 200, 300, 400].map((b, i) => ({ age_s: 15 - 5 * i, bps: b * 1000 })) },
    relays: [{ name: '<img src=x onerror=alert(1)>', state: 'failed', last_error: 'The destination refused the connection. (exit code 1)' }],
    recorder: { state: 'recording', waiting_chunks: 2, waiting_bytes: 3 * 1048576 },
    warnings: [{ code: 'relay_failing', level: 'warn', text: 'A relay is failing.' }],
  };
  answer = () => ({ status: 200, ok: true, json: async () => report });
  const btn = new N('BUTTON');
  const panel = ctx.StreamHealth.mount({ button: btn, streamId: 5 });
  await new Promise(r => setImmediate(r));
  check('nothing is fetched or polled while the panel is closed', fetchCalls.length === 0 && intervals.length === 0);
  await btn.fire('click');
  await new Promise(r => setImmediate(r));
  check('opening fetches the health route once and starts one poll', fetchCalls.length === 1 && fetchCalls[0].url === '/api/streams/5/health' && intervals.length === 1 && intervals[0].ms >= 3000 && intervals[0].ms <= 5000, JSON.stringify(fetchCalls.map(f => f.url)) + intervals.length);
  const text = panel.panel.textContent;
  check('it shows bitrate, uptime, source, codecs, relay, recorder and warning', ['850 kbit/s', '1 h 1 min', 'RTMP', 'H264, MPEG-4 Audio', 'failing', '2 finished chunk(s)', 'A relay is failing.', 'What the server receives'].every(s => text.includes(s)), text);
  const svgs = panel.panel.find(n => n.tagName === 'SVG'); const lines = panel.panel.find(n => n.tagName === 'POLYLINE');
  check('the sparkline is built from DOM calls: one svg with one polyline of 4 points', svgs.length === 1 && lines.length === 1 && lines[0].attrs.points.split(' ').length === 4, lines.map(l => l.attrs.points));
  check('relay text from the server stays text (no markup was written)', panel.panel.find(n => n.innerHTMLWrites > 0).length === 0 && text.includes('<img src=x onerror=alert(1)>'));
  // a relay an administrator stopped is not a failure
  const body2 = new N('DIV');
  ctx.StreamHealth.render(body2, { live: true, uptime_s: 5, ingest: { available: false, reason: 'x' },
    relays: [{ name: 'Twitch', state: 'stopped_by_admin', last_error: null }], recorder: { state: 'not_recording' }, warnings: [] });
  const t2 = body2.textContent;
  check('a relay stopped by an administrator is shown as that, not as failing', t2.includes('Twitch: stopped by an administrator') && !t2.includes('failing') && !t2.includes('exit code'), t2);
  check('the panel says how coarse the readings are', t2.includes('every 30 seconds') && t2.includes('75 seconds'), t2);
  check('the Stop relays question says what a restart does', ctx.LiveOpsAdmin.questionText('stop-relays', 'S', true).includes('restarted'));
  // polling only while visible
  ctx.document.hidden = true; ctx.document.visibilityState = 'hidden';
  await intervals[0].f(); await new Promise(r => setImmediate(r));
  check('a hidden tab does not poll', fetchCalls.length === 1);
  ctx.document.hidden = false; ctx.document.visibilityState = 'visible';
  for (const f of docListeners.visibilitychange || []) await f();
  await new Promise(r => setImmediate(r));
  check('coming back refreshes at once', fetchCalls.length === 2);
  await btn.fire('click');
  check('closing stops the poll', cleared.length >= 1 && !panel.isOpen());
  await intervals[0].f(); await new Promise(r => setImmediate(r));
  check('a poll that fires after closing fetches nothing', fetchCalls.length === 2);
  // a 404 (not the owner) stops for good
  answer = () => ({ status: 404, ok: false, json: async () => ({}) });
  await btn.fire('click'); await new Promise(r => setImmediate(r));
  const n404 = fetchCalls.length;
  check('a 404 shows a plain message', panel.panel.textContent.includes('not available for this account'));
  await panel.refresh(); await new Promise(r => setImmediate(r));
  check('and nothing more is fetched after a 404', fetchCalls.length === n404);
  // not live / no numbers
  const p2 = ctx.StreamHealth.mount({ button: new N('BUTTON'), streamId: 6 });
  answer = () => ({ status: 200, ok: true, json: async () => ({ live: true, uptime_s: 5, ingest: { available: false, reason: 'This server is not collecting ingest numbers for this stream.' }, relays: [], recorder: { state: 'not_recording' }, warnings: [] }) });
  p2.open(); await new Promise(r => setImmediate(r));
  check('without ingest numbers the panel says why, with no chart', p2.panel.textContent.includes('not collecting ingest numbers') && p2.panel.find(n => n.tagName === 'SVG').length === 0);

  // ---- the administrator's list
  const rows = [{ id: 7, name: 'Night <b>show</b>', owner: 'alice', uptime_s: 4000, bitrate_bps: null, viewers: 3, relays_running: 1, recording: true }];
  const calls = [];
  let hold = null;
  const api = async (kind, id, bodyObj) => {
    calls.push({ kind, id, body: bodyObj });
    if (kind === 'list') return { ok: true, data: { streams: rows } };
    if (hold) await hold;
    return { ok: true, data: kind === 'end' ? { publisher_disconnected: true } : { stopped: 1 } };
  };
  const tbody = new N('TBODY'); const note = new N('P');
  const ctl = ctx.LiveOpsAdmin.mount({ tbody, note, isShown: () => true }, api);
  await ctl.load();
  const clickable = (label) => tbody.find(n => n.tagName === 'BUTTON' && n.textContent === label)[0];
  check('the list shows the stream as text, with "not collected" for a missing bitrate', tbody.textContent.includes('Night <b>show</b>') && tbody.textContent.includes('not collected') && tbody.find(n => n.innerHTMLWrites > 0).length === 0);
  await clickable('End now').fire('click');
  const q = tbody.find(n => n.className === 'live-ops-confirm')[0];
  check('End now asks first and states chat, key and recordings', q && ['chat', 'stream key is replaced', 'no recording is deleted', 'administrator ended'].every(s => q.textContent.includes(s)), q && q.textContent);
  check('nothing was sent by the first click', calls.filter(c => c.kind === 'end').length === 0);
  const confirmRowBtn = () => tbody.find(n => n.tagName === 'BUTTON' && n.textContent === 'Yes, end the stream')[0];
  const opener = clickable('End now');
  const rowOf = (b) => tbody.children.findIndex(tr => tr.find && tr.find(n => n === b).length);
  check('the confirm button is on its own row, not in the row of the opener', rowOf(confirmRowBtn()) !== rowOf(opener) && rowOf(confirmRowBtn()) >= 0);
  await confirmRowBtn().fire('click', { detail: 1 });
  check('a confirm within 0.6 s of the question is ignored', calls.filter(c => c.kind === 'end').length === 0);
  clock += 700;
  await confirmRowBtn().fire('click', { detail: 2 });
  check('the second click of a double click is ignored', calls.filter(c => c.kind === 'end').length === 0);
  const cb = tbody.find(n => n.tagName === 'INPUT')[0];
  check('the key box starts checked (default on)', cb.checked === true);
  cb.checked = false; await cb.fire('change');
  check('unchecking changes what the question says', tbody.find(n => n.className === 'live-ops-confirm')[0].textContent.includes('The stream key stays as it is'));
  let release; hold = new Promise(r => { release = r; });
  const first = confirmRowBtn().fire('click', { detail: 1 });
  await new Promise(r => setImmediate(r));
  await ctl.run({ detail: 1 });
  release(); await first;
  const ends = calls.filter(c => c.kind === 'end');
  check('one request only, with the choice of the box, while one is in flight', ends.length === 1 && ends[0].id === 7 && ends[0].body.regenerate_key === false, JSON.stringify(ends));
  hold = null;
  await clickable('Stop relays').fire('click');
  check('Stop relays asks first too', tbody.find(n => n.className === 'live-ops-confirm')[0].textContent.includes('relays') && calls.filter(c => c.kind === 'stop-relays').length === 0);
  clock += 700;
  await tbody.find(n => n.tagName === 'BUTTON' && n.textContent === 'Yes, stop the relays')[0].fire('click', { detail: 1 });
  check('and then sends it', calls.filter(c => c.kind === 'stop-relays').length === 1);
  console.log(results.map(r => 'RESULT ' + JSON.stringify(r)).join('\n'));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'the harness ran', ok: false, detail: String(e && e.stack || e) })); });

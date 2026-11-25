// Loads static/js/portal.js, then stream-health.js and live-ops-admin.js the way a browser does (separate
// classic scripts in one vm context sharing only the global object) and drives them against a tiny fake DOM and
// a fake fetch. No browser: layout, real timers and real SVG rendering are not covered.
// usage: node stream_health_client_harness.js <portal.js> <stream-health.js> <live-ops-admin.js>
'use strict';
const fs = require('fs');
const vm = require('vm');
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }
// A check that needs its own deadline: a hang prints FAIL for that check instead of stalling the whole file.
async function withDeadline(name, fn, ms) {
  let timer;
  const late = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('no answer within ' + (ms || 5000) + ' ms')), ms || 5000); });
  try { await Promise.race([fn(), late]); } catch (e) { check(name + ' (did not finish)', false, e && e.message); } finally { clearTimeout(timer); }
}

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
  await withDeadline('the graph scales to the panel', async () => {
    const a = svgs[0].attrs;
    check('the sparkline scales to the panel: width 100 percent, a viewBox, no fixed pixel width or height', a.width === '100%' && a.viewBox === '0 0 280 60' && !('height' in a), JSON.stringify(a));
    const b3 = new N('DIV');
    ctx.StreamHealth.render(b3, { live: true, uptime_s: 5, ingest: { available: false, reason: 'x' }, relays: [], recorder: { state: 'not_recording' },
      warnings: [{ code: 'no_data', level: 'error', text: 'No data.' }, { code: 'relay_failing', level: 'warn', text: 'A relay.' }] });
    const cls = b3.find(n => n.className && n.className.split(' ').indexOf('stream-health-warning') >= 0).map(n => n.className);
    check('each warning carries its level as a class, so the page can colour it', cls.length === 2 && cls[0].split(' ').indexOf('stream-health-error') >= 0 && cls[1].split(' ').indexOf('stream-health-warn') >= 0, cls);
  });
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
  check('one request only, with the choice of the box, while one is in flight', ends.length === 1 && ends[0].id === 7 && ends[0].body.regenerate_key === false && ends[0].body.confirm === true, JSON.stringify(ends));
  hold = null;
  await clickable('Stop relays').fire('click');
  check('Stop relays asks first too', tbody.find(n => n.className === 'live-ops-confirm')[0].textContent.includes('relays') && calls.filter(c => c.kind === 'stop-relays').length === 0);
  clock += 700;
  await tbody.find(n => n.tagName === 'BUTTON' && n.textContent === 'Yes, stop the relays')[0].fire('click', { detail: 1 });
  check('and then sends it', calls.filter(c => c.kind === 'stop-relays').length === 1);
  // ---- an open question survives the refresh
  await withDeadline('the refresh leaves an open question alone', async () => {
    let rows2 = [{ id: 9, name: 'Quiet hour', owner: 'bob', uptime_s: 60, bitrate_bps: null, viewers: 1, relays_running: 0, recording: false }];
    const lists = [];
    const api2 = async (kind) => { lists.push(kind); return { ok: true, data: { streams: rows2 } }; };
    const tb = new N('TBODY');
    const c2 = ctx.LiveOpsAdmin.mount({ tbody: tb, note: new N('P'), isShown: () => true }, api2);
    await c2.load();
    await tb.find(n => n.tagName === 'BUTTON' && n.textContent === 'End now')[0].fire('click');
    const yes = tb.find(n => n.tagName === 'BUTTON' && n.textContent === 'Yes, end the stream')[0];
    check('the question is a row of its own, full width, that the page can style', tb.find(n => n.className === 'live-ops-confirm-row' && n.children[0].attrs.colspan === '8').length === 1);
    const askedAt = c2.state.asking.at;
    const n0 = lists.length;
    rows2 = [Object.assign({}, rows2[0], { uptime_s: 3700, viewers: 5 })];
    await c2.load();
    check('a refresh reads the list again', lists.length === n0 + 1);
    check('with the question open the confirm button is the same element, still in the table', tb.find(n => n === yes).length === 1);
    check('and the question keeps its guard time', c2.state.asking && c2.state.asking.at === askedAt);
    await tb.find(n => n.tagName === 'BUTTON' && n.textContent === 'Keep it as it is')[0].fire('click');
    check('cancelling shows the list as the last refresh read it', tb.find(n => n.className === 'live-ops-confirm').length === 0 && tb.textContent.includes('1 h 1 min') && tb.textContent.includes('5'));
    await tb.find(n => n.tagName === 'BUTTON' && n.textContent === 'End now')[0].fire('click');
    rows2 = [];
    await c2.load();
    check('a stream that ended meanwhile closes its question', tb.find(n => n.className === 'live-ops-confirm').length === 0 && tb.textContent.includes('No stream is live.'));
  });
  // ---- the figures keep moving while a question is open
  await withDeadline('the figures of the rows keep moving while a question is open', async () => {
    let rows3 = [
      { id: 1, name: 'First', owner: 'a', uptime_s: 60, bitrate_bps: 1000000, viewers: 1, relays_running: 0, recording: false },
      { id: 2, name: 'Second', owner: 'b', uptime_s: 120, bitrate_bps: null, viewers: 2, relays_running: 1, recording: false },
    ];
    const api3 = async () => ({ ok: true, data: { streams: rows3 } });
    const tb = new N('TBODY');
    const c3 = ctx.LiveOpsAdmin.mount({ tbody: tb, note: new N('P'), isShown: () => true }, api3);
    await c3.load();
    const btn = (t) => tb.find(n => n.tagName === 'BUTTON' && n.textContent === t);
    await btn('End now')[0].fire('click');                      // ask about the first stream
    const yes = btn('Yes, end the stream')[0], endSecond = btn('End now')[1], stopSecond = btn('Stop relays')[1], keep = btn('Keep it as it is')[0];
    const cb = tb.find(n => n.tagName === 'INPUT')[0];
    const confirmRow = tb.find(n => n.className === 'live-ops-confirm-row')[0];
    const row2 = tb.children.find(tr => tr.find && tr.find(n => n === endSecond).length);
    rows3 = [
      Object.assign({}, rows3[0], { uptime_s: 3700, viewers: 5, bitrate_bps: 2500000 }),
      Object.assign({}, rows3[1], { uptime_s: 7300, viewers: 9, relays_running: 2, recording: true }),
    ];
    await c3.load();
    const text = tb.textContent, t2 = row2.textContent;
    check('another row shows the new viewers, uptime, relays and recording while the question is open', t2.includes('2 h 1 min') && t2.includes('not collected9') && t2.includes('2 running') && t2.includes('running' + 'recording'), t2);
    check('the open row shows its new figures too', text.includes('1 h 1 min') && text.includes('2.50 Mbit/s'), text);
    check('the old figures are gone', !text.includes('2 min 0 s') && !text.includes('1 min 0 s'), text);
    check('the question and its buttons are the same elements', tb.find(n => n === yes).length === 1 && tb.find(n => n === keep).length === 1 && tb.find(n => n === cb).length === 1 && tb.find(n => n === confirmRow).length === 1);
    check('the buttons of the other row are the same elements and the row is not rebuilt', tb.find(n => n === endSecond).length === 1 && tb.find(n => n === stopSecond).length === 1 && tb.children.includes(row2));
    check('the question still keeps its guard time and its place', c3.state.asking && c3.state.asking.id === 1 && tb.find(n => n.className === 'live-ops-confirm').length === 1);
    clock += 700;
    const first = yes.fire('click', { detail: 1 });
    await first;
    check('the confirm button still works after the figures moved', c3.state.asking === null);
  });
  console.log(results.map(r => 'RESULT ' + JSON.stringify(r)).join('\n'));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'the harness ran', ok: false, detail: String(e && e.stack || e) })); });

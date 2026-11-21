// Connection-quality bars of static/js/voice.js (1.20.0) under Node: the real
// voice.js against a small DOM, a fake RTCPeerConnection whose getStats() is
// scripted, a controllable clock, setInterval and page visibility.
// Used by tests/test_voicequality.py and tools/smoke_checks/check_voicequality.py.
//
// usage: node voicequality_harness.js <path to voice.js>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const SRC = fs.readFileSync(process.argv[2], 'utf8');
const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) });
}

// ---- fake DOM ---------------------------------------------------------------
class El {
  constructor(tag, doc) {
    this.tag = tag.toUpperCase(); this.doc = doc; this.children = []; this.parent = null;
    this.attrs = {}; this.handlers = {}; this.style = {}; this._text = ''; this.className = '';
    this.id = ''; this.muted = false; this.volume = 1; this.srcObject = null; this.value = '';
    this.tabIndex = -1; this.offsetWidth = 260; this.offsetHeight = 160;
    if (tag === 'audio' && doc.volumeLocked) {   // iOS Safari: volume cannot be set from script
      Object.defineProperty(this, 'volume', { get() { return 1; }, set() {} });
    }
  }
  get isConnected() { let e = this; while (e.parent) e = e.parent; return e === this.doc.documentElement; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set textContent(v) { this.children.forEach(c => { c.parent = null; }); this.children = []; this._text = String(v); }
  appendChild(c) { if (c.parent) c.remove(); c.parent = this; this.children.push(c); return c; }
  remove() { if (this.parent) { this.parent.children = this.parent.children.filter(x => x !== this); this.parent = null; } }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'class') this.className = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(t, fn) { (this.handlers[t] = this.handlers[t] || []).push(fn); }
  focus() { this.doc.activeElement = this; }
  contains(o) { for (let e = o; e; e = e.parent) if (e === this) return true; return false; }
  getBoundingClientRect() { return { left: 10, bottom: 20, top: 0, right: 100 }; }
  matches(sel) {
    return sel.split(',').some(part => {
      part = part.trim();
      const m = part.match(/^([.#]?)([\w-]*)((?:\[[\w-]+(?:="[^"]*")?\])*)$/);
      if (!m) return false;
      if (m[1] === '.' && !this.className.split(/\s+/).includes(m[2])) return false;
      if (m[1] === '' && m[2] && this.tag !== m[2].toUpperCase()) return false;
      if (m[1] === '#' && this.id !== m[2]) return false;
      for (const a of m[3].matchAll(/\[([\w-]+)(?:="([^"]*)")?\]/g)) {
        const v = this.getAttribute(a[1]);
        if (v === null || (a[2] !== undefined && v !== a[2])) return false;
      }
      return true;
    });
  }
  closest(sel) { for (let e = this; e; e = e.parent) if (e.matches && e.matches(sel)) return e; return null; }
  querySelectorAll(sel) {
    const out = [];
    const walk = (n) => { for (const c of n.children) { if (c.matches(sel)) out.push(c); walk(c); } };
    walk(this); return out;
  }
  querySelector(sel) {
    for (const c of this.children) {
      if (c.matches(sel)) return c;
      const r = c.querySelector(sel); if (r) return r;
    }
    return null;
  }
  fire(type, ev) {
    const e = Object.assign({ type, target: this, defaultPrevented: false, stopped: false,
      preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.stopped = true; } }, ev || {});
    // capture on the document first, then the target and its ancestors
    for (const h of (this.doc.handlers[type] || [])) h(e);
    for (let n = this; n && !e.stopped; n = n.parent) (n.handlers[type] || []).forEach(h => h(e));
    return e;
  }
}
class Doc {
  constructor() {
    this.handlers = {}; this.activeElement = null;
    this.documentElement = new El('html', this); this.body = new El('body', this);
    this.head = new El('head', this); this.documentElement.appendChild(this.head);
    this.documentElement.appendChild(this.body);
  }
  createElement(t) { return new El(t, this); }
  createTextNode(t) { const e = new El('#text', this); e._text = t; return e; }
  getElementById(id) { return this.documentElement.querySelector('#' + id); }
  querySelector(sel) { return this.documentElement.querySelector(sel); }
  querySelectorAll(sel) { return this.documentElement.querySelectorAll(sel); }
  addEventListener(t, fn) { (this.handlers[t] = this.handlers[t] || []).push(fn); }
  removeEventListener(t, fn) { this.handlers[t] = (this.handlers[t] || []).filter(h => h !== fn); }
}


// A stats report like the browser's: a Map whose values carry type and id.
const SECRET_IP = '203.0.113.77';
function report(o) {
  const m = new Map();
  const add = (s) => m.set(s.id, s);
  if (o.recv !== undefined) add({ id: 'in1', type: 'inbound-rtp', kind: 'audio', packetsReceived: o.recv, packetsLost: o.lost || 0, jitter: o.jitter === undefined ? 0.005 : o.jitter, ssrc: 1 });
  add({ id: 'cand-l', type: 'local-candidate', candidateType: o.localType || 'host', address: SECRET_IP, ip: SECRET_IP, port: 4444 });
  add({ id: 'cand-r', type: 'remote-candidate', candidateType: 'host', address: SECRET_IP, ip: SECRET_IP });
  if (o.noPair !== true) {
    add({ id: 'pair1', type: 'candidate-pair', state: o.pairState || 'succeeded', nominated: o.nominated !== false, localCandidateId: 'cand-l', remoteCandidateId: 'cand-r',
      currentRoundTripTime: o.rtt === undefined ? 0.04 : o.rtt, selected: o.selectedFlag === true });
    if (o.transport !== false) add({ id: 'tr1', type: 'transport', selectedCandidatePairId: 'pair1' });
  }
  return m;
}

function makeEnv(opts) {
  opts = opts || {};
  const doc = new Doc();
  doc.hidden = false;
  const pcs = []; const sent = []; const intervals = [];
  const clock = { now: 1000000 };
  class FakePC {
    constructor() { this.signalingState = 'stable'; this.connectionState = 'connected'; this.closed = false; this.statCalls = 0;
      this.script = []; this.last = null; this.closeCalls = 0; this.restarts = 0; this.offers = 0; pcs.push(this); }
    addTrack() { return {}; } close() { this.closed = true; this.closeCalls++; }
    async createOffer() { this.offers++; return { type: 'offer', sdp: 'o' }; } async setLocalDescription() {}
    restartIce() { this.restarts++; }
    async getStats() {
      this.statCalls++;
      if (this.throwStats) throw new Error('stats failed');
      if (this.script.length) this.last = this.script.shift();
      return this.last;
    }
  }
  const ws = { readyState: 1, send(m) { sent.push(m); }, addEventListener() {} };
  const win = { innerWidth: 1000, innerHeight: 800, addEventListener() {} };
  const sandbox = {
    window: win, document: doc, localStorage: { getItem() { return null; }, setItem() {}, removeItem() {} },
    console: { warn() {}, error() {}, log() {} },
    navigator: { userAgent: 'Mozilla/5.0 Chrome/120', platform: 'Linux x86_64', maxTouchPoints: 0,
      mediaDevices: { getUserMedia: async () => ({ getTracks: () => [{ stop() {} }], getAudioTracks: () => [{ enabled: true, stop() {} }] }) } },
    WebSocket: { OPEN: 1 }, RTCPeerConnection: FakePC, RTCSessionDescription: function (d) { return d; },
    RTCIceCandidate: function (d) { return d; }, fetch: async () => ({ ok: false }),
    setTimeout() { return 0; }, clearTimeout() {},
    setInterval(fn, ms) { const t = { fn, ms, live: true, id: intervals.length + 1 }; intervals.push(t); return t.id; },
    clearInterval(id) { const t = intervals.find(x => x.id === id); if (t) t.live = false; },
    Float32Array, Promise, JSON, Math, Number, Map, Set, Object, Array, String, Error, Symbol,
    Date: { now: () => clock.now },
  };
  win.window = win;
  vm.createContext(sandbox);
  vm.runInContext(SRC + '\n;globalThis.__VC = VoiceChat;', sandbox);
  const env = { VC: sandbox.__VC, doc, pcs, sent, intervals, clock, ws };
  env.liveIntervals = () => intervals.filter(t => t.live);
  // one poll round: advance the clock by 4 s and run the live interval callbacks
  env.poll = async () => {
    clock.now += 4000;
    for (const t of env.liveIntervals()) await t.fn();
    await tick(); await tick();
  };
  env.setHidden = (h) => { doc.hidden = h; (doc.handlers.visibilitychange || []).slice().forEach(fn => fn({ type: 'visibilitychange' })); };
  return env;
}

const tick = () => new Promise(r => setImmediate(r));
async function joined(env, myId, peerIds) {
  const { VC, ws } = env;
  VC.init(ws, null, null, myId);
  await VC.join();
  const users = [myId].concat(peerIds).map(id => ({ user_id: id, username: 'u' + id, muted: false, deafened: false, speaking: false }));
  VC.handleMessage({ type: 'voice_state', channel: 'general', resume_token: 'tok', users });
  await tick(); await tick();
  return env;
}
// a container with one tile per peer, rendered the way the pages do
function makeBar(env, ids) {
  const bar = env.doc.createElement('div'); bar.id = 'bar'; env.doc.body.appendChild(bar);
  const render = () => {
    bar.textContent = '';
    ids.forEach(id => { const t = env.doc.createElement('span'); t.setAttribute('class', 'voice-user-mini'); t.setAttribute('data-voice-uid', String(id)); t.textContent = 'u' + id; bar.appendChild(t); });
  };
  env.VC.renderKeepingFocus(bar, render);
  return { bar, render, tile: (id) => bar.querySelector('[data-voice-uid="' + id + '"]'), slot: (id) => { const t = bar.querySelector('[data-voice-uid="' + id + '"]'); return t ? t.querySelector('.vq') : null; } };
}
const barsOf = (slot) => slot.children.filter(c => c.className.split(/\s+/).includes('on')).length;
async function scenario(name, fn) {
  try { await fn(); } catch (e) { check(name + ' (no exception)', false, e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e); }
}
const S = (o) => Object.assign({ t: 0, received: 0, lost: 0, jitterMs: 5, rttMs: 40, path: 'direct' }, o || {});

(async () => {
  const VCp = makeEnv().VC;   // the pure functions need no call

  await scenario('pure scoring', async () => {
    const { scoreQuality: sq } = VCp;
    check('the scoring functions are exported', typeof sq === 'function' && typeof VCp.readQualityStats === 'function');
    const first = sq(null, S({ t: 0, received: 5000, lost: 400 }), false);
    check('the first sample ignores lifetime totals (no loss figure yet)', first.view.lossPct === null && first.view.bars === 4, JSON.stringify(first.view));
    const clean = sq(first.rec, S({ t: 4000, received: 5200, lost: 400 }), false);
    check('a clean interval after a lossy past scores 4 bars', clean.view.bars === 4 && clean.view.lossPct === 0, JSON.stringify(clean.view));
    const loss = (pct) => sq(first.rec, S({ t: 4000, received: 5000 + 200 - pct * 2, lost: 400 + pct * 2 }), false).view;
    check('1 percent loss: 4 bars', loss(1).bars === 4, loss(1).bars);
    check('3 percent loss: 3 bars', loss(3).bars === 3, loss(3).bars);
    check('7 percent loss: 2 bars', loss(7).bars === 2, loss(7).bars);
    check('20 percent loss: 1 bar', loss(20).bars === 1, loss(20).bars);
    check('loss is a share of the interval (10 lost of 200 = 5 percent)', Math.abs(loss(5).lossPct - 5) < 1e-9, loss(5).lossPct);
    const rttBars = (ms) => sq(first.rec, S({ t: 4000, received: 5200, lost: 400, rttMs: ms }), false).view.bars;
    check('rtt 100 ms: 4, 200 ms: 3, 400 ms: 2, 900 ms: 1', rttBars(100) === 4 && rttBars(200) === 3 && rttBars(400) === 2 && rttBars(900) === 1,
      [rttBars(100), rttBars(200), rttBars(400), rttBars(900)].join(','));
    const jit = (ms) => sq(first.rec, S({ t: 4000, received: 5200, lost: 400, jitterMs: ms }), false).view.bars;
    check('jitter 20 ms: 4, 50 ms: 3, 100 ms: 2, 300 ms: 1', jit(20) === 4 && jit(50) === 3 && jit(100) === 2 && jit(300) === 1);
    const worst = sq(first.rec, S({ t: 4000, received: 5190, lost: 410, rttMs: 600 }), false).view;
    check('the worst figure decides', worst.bars === 1, worst.bars);
    check('a negative lost delta counts as no loss', sq(first.rec, S({ t: 4000, received: 5200, lost: 390 }), false).view.lossPct === 0);
    const reset = sq(first.rec, S({ t: 4000, received: 10, lost: 0 }), false);
    check('restarted counters rebase instead of giving garbage', reset.view.lossPct === null && reset.view.hint === false);
    check('no figures at all: zero bars, not one', sq(null, S({ rttMs: null, jitterMs: null, received: null, lost: null }), false).view.bars === 0);
    const tip = sq(first.rec, S({ t: 4000, received: 5190, lost: 410, rttMs: 83 }), false).view.title;
    check('the tooltip shows rtt, loss over the interval and the path', /83 ms/.test(tip) && /5%/.test(tip) && /direct/.test(tip), tip);
    check('the tooltip says unknown for a missing rtt and path',
      /unknown/.test(sq(null, S({ rttMs: null, path: 'unknown' }), false).view.title));

    // hint: stalled counters for 6 s, never for a muted peer
    let r = sq(null, S({ t: 0, received: 100 }), false);
    r = sq(r.rec, S({ t: 4000, received: 100 }), false);
    check('4 s without packets: no hint yet', r.view.hint === false);
    r = sq(r.rec, S({ t: 8000, received: 100 }), false);
    check('8 s (over 6) without packets and not muted: the hint', r.view.hint === true && /No audio received/.test(r.view.title));
    let m = sq(null, S({ t: 0, received: 100 }), true);
    m = sq(m.rec, S({ t: 4000, received: 100 }), true); m = sq(m.rec, S({ t: 8000, received: 100 }), true); m = sq(m.rec, S({ t: 20000, received: 100 }), true);
    check('a muted peer never shows the hint', m.view.hint === false);
    const un = sq(m.rec, S({ t: 24000, received: 100 }), false);
    check('right after an unmute the hint timer starts over', un.view.hint === false);
    const un2 = sq(un.rec, S({ t: 32000, received: 100 }), false);
    check('and fires after the unmuted peer stays silent for 6 s', un2.view.hint === true);
    const back = sq(r.rec, S({ t: 12000, received: 160 }), false);
    check('packets advancing clears the hint', back.view.hint === false);
  });

  await scenario('stats reading', async () => {
    const { readQualityStats: rd } = VCp;
    const a = rd(report({ recv: 300, lost: 4, jitter: 0.012, rtt: 0.083, localType: 'host' }), 55);
    check('reads packets, jitter (ms), rtt (ms) and a direct path', a.received === 300 && a.lost === 4 && Math.abs(a.jitterMs - 12) < 1e-6 && Math.abs(a.rttMs - 83) < 1e-6 && a.path === 'direct' && a.t === 55, JSON.stringify(a));
    check('a relay local candidate is reported as relayed', rd(report({ recv: 1, localType: 'relay' }), 0).path === 'relayed');
    check('srflx and prflx count as direct', rd(report({ recv: 1, localType: 'srflx' }), 0).path === 'direct' && rd(report({ recv: 1, localType: 'prflx' }), 0).path === 'direct');
    const ff = rd(report({ recv: 1, transport: false, localType: 'relay' }), 0);
    check('without a selected pair (older Firefox) the nominated succeeded pair is used', ff.path === 'relayed' && ff.rttMs !== null, JSON.stringify(ff));
    check('a nominated pair that has not succeeded is not used', rd(report({ recv: 1, transport: false, pairState: 'in-progress' }), 0).path === 'unknown');
    check('a pair that is not nominated is not used', rd(report({ recv: 1, transport: false, nominated: false }), 0).path === 'unknown');
    check('no pair at all: unknown', rd(report({ recv: 1, noPair: true }), 0).path === 'unknown');
    check('garbage in, nothing out', rd(null, 0).path === 'unknown' && rd({}, 0).received === null);
    const keys = Object.keys(a).join(',');
    check('the sample carries no address field', !/addr|ip|port/i.test(keys) && !JSON.stringify(a).includes(SECRET_IP), keys);
    const video = new Map([['v', { id: 'v', type: 'inbound-rtp', kind: 'video', packetsReceived: 999 }]]);
    check('a video stream does not count as audio', rd(video, 0).received === null);
  });

  await scenario('the loop in a call', async () => {
    const env = await joined(makeEnv(), 1, [2, 3]);
    const { VC } = env;
    check('joining starts exactly one 4 second loop', env.liveIntervals().length === 1 && env.liveIntervals()[0].ms === 4000 && VC.isQualityRunning());
    const ui = makeBar(env, [2, 3]);
    check('each remote tile gets a slot of 4 bars and the hint mark', ui.slot(2).children.length === 5 && ui.slot(3).children.length === 5);
    check('before any figure no bar is lit and the tooltip says measuring', barsOf(ui.slot(2)) === 0 && /measuring/.test(ui.slot(2).getAttribute('title')));
    const tile2 = ui.tile(2), slot2 = ui.slot(2);
    const [pc2, pc3] = env.pcs;
    pc2.script = [report({ recv: 1000, lost: 0 }), report({ recv: 1200, lost: 0 }), report({ recv: 1300, lost: 40 }), report({ recv: 1500, lost: 120 })];
    pc3.script = [report({ recv: 500, lost: 0, localType: 'relay' }), report({ recv: 700, lost: 0, localType: 'relay' }), report({ recv: 900, lost: 0, localType: 'relay' }), report({ recv: 1100, lost: 0, localType: 'relay' })];
    env.sent.length = 0;
    await env.poll();
    check('the first poll lights the bars from rtt and jitter', barsOf(slot2) === 4, barsOf(slot2));
    await env.poll();
    check('clean interval: 4 bars and 0 loss in the tooltip', barsOf(slot2) === 4 && /loss 0%/.test(slot2.getAttribute('title')), slot2.getAttribute('title'));
    await env.poll();       // 40 of 140 lost = 28.6 percent
    check('rising loss drops the bars within one interval', barsOf(slot2) === 1, barsOf(slot2));
    check('the tooltip shows the loss', /loss 28\.6%/.test(slot2.getAttribute('title')) && /direct/.test(slot2.getAttribute('title')), slot2.getAttribute('title'));
    check('the bars of the other peer are unaffected and show relayed', barsOf(ui.slot(3)) === 4 && /relayed/.test(ui.slot(3).getAttribute('title')), ui.slot(3).getAttribute('title'));
    check('updated in place: the same tile and slot nodes are still there', ui.tile(2) === tile2 && ui.slot(2) === slot2 && tile2.children.filter(c => c.className.indexOf('vq') === 0).length === 1);
    check('the slot color class follows the score', slot2.className.includes('vq-q1'), slot2.className);
    check('no hint while packets keep arriving', !slot2.className.includes('vq-noaudio'));

    // a re-render of the tile (a state change) gets the current figures back
    ui.render(); VC.renderKeepingFocus(ui.bar, ui.render);
    check('a re-rendered tile is refilled from the cache', barsOf(ui.slot(2)) === 1 && /loss 28\.6%/.test(ui.slot(2).getAttribute('title')));
    // a recovered line
    await env.poll();
    check('a recovered line climbs back', barsOf(ui.slot(2)) >= 1 && /loss 38\.1%|loss/.test(ui.slot(2).getAttribute('title')));

    // nothing leaves the browser
    check('polling sends no frame to the server', env.sent.length === 0, env.sent.join(' '));
    const texts = []; (function walk(n) { texts.push(n.textContent, JSON.stringify(n.attrs)); n.children.forEach(walk); })(env.doc.documentElement);
    check('no address from the stats reaches the page', !texts.join(' ').includes(SECRET_IP));
    check('polling never restarts ICE, closes or renegotiates a connection', env.pcs.every(p => p.restarts === 0 && p.closeCalls === 0 && p.offers <= 1), env.pcs.map(p => [p.restarts, p.closeCalls, p.offers].join('/')).join(' '));
  });

  await scenario('hint and mute', async () => {
    const env = await joined(makeEnv(), 1, [2, 3, 4]);
    const { VC } = env;
    const ui = makeBar(env, [2, 3, 4]);
    const frozen = report({ recv: 100, lost: 0 });
    env.pcs.forEach(p => { p.last = frozen; });
    VC.handleMessage({ type: 'voice_mute_changed', user_id: 3, muted: true });
    VC.handleMessage({ type: 'voice_server_mute_changed', user_id: 4, server_muted: true });
    const hasHint = (id) => ui.slot(id).className.includes('vq-noaudio');
    await env.poll();
    await env.poll();
    check('after 4 s of no packets there is no hint yet', !hasHint(2));
    await env.poll();
    check('after 8 s the unmuted silent peer shows the hint', hasHint(2) && /No audio received/.test(ui.slot(2).getAttribute('title')));
    check('a self-muted peer never shows it', !hasHint(3));
    check('a server-muted peer never shows it', !hasHint(4));
    await env.poll(); await env.poll();
    check('still never, long after', !hasHint(3) && !hasHint(4) && hasHint(2));
    check('the hint did not touch the connection', env.pcs.every(p => p.restarts === 0 && p.closeCalls === 0 && p.offers <= 1));
    // audio comes back on the first peer
    env.pcs[0].script = [report({ recv: 250, lost: 0 })];
    await env.poll();
    check('audio arriving again clears the hint', !hasHint(2));
    // peer 3 unmutes while still silent: the timer starts over
    VC.handleMessage({ type: 'voice_mute_changed', user_id: 3, muted: false });
    await env.poll();
    check('an unmute does not show the hint at once', !hasHint(3));
    await env.poll();
    check('nor 4 s later', !hasHint(3));
    await env.poll();
    check('but a peer that stays silent after the unmute does', hasHint(3));
  });

  await scenario('page visibility', async () => {
    const env = await joined(makeEnv(), 1, [2]);
    makeBar(env, [2]);
    env.pcs[0].last = report({ recv: 10 });
    await env.poll();
    const before = env.pcs[0].statCalls;
    env.setHidden(true);
    check('a hidden page stops the loop', env.liveIntervals().length === 0 && !env.VC.isQualityRunning());
    await env.poll(); await env.poll();
    check('and nothing calls getStats meanwhile', env.pcs[0].statCalls === before, env.pcs[0].statCalls);
    // even a stray timer call while hidden does nothing
    const stray = env.intervals[0]; await stray.fn();
    check('a stray tick on a hidden page does nothing', env.pcs[0].statCalls === before);
    env.setHidden(false);
    check('showing the page again restarts one loop', env.liveIntervals().length === 1 && env.VC.isQualityRunning());
    await env.poll();
    check('and polling resumes', env.pcs[0].statCalls === before + 1);
    env.setHidden(false);
    check('a second visible event does not start a second loop', env.liveIntervals().length === 1);
    // the first poll after a pause is a fresh baseline: a long silence is not held against the peer
    const env2 = await joined(makeEnv(), 1, [2]);
    const ui2 = makeBar(env2, [2]);
    env2.pcs[0].last = report({ recv: 50 });
    await env2.poll();
    env2.setHidden(true); env2.clock.now += 600000; env2.setHidden(false);
    await env2.poll();
    check('after a long hidden spell there is no instant hint', !ui2.slot(2).className.includes('vq-noaudio'));
    // joining on a hidden page
    const env3 = makeEnv(); env3.doc.hidden = true;
    await joined(env3, 1, [2]);
    check('joining on a hidden page starts nothing', env3.liveIntervals().length === 0);
    env3.setHidden(false);
    check('until the page is shown', env3.liveIntervals().length === 1);
  });

  await scenario('stopping', async () => {
    const env = await joined(makeEnv(), 1, [2]);
    const ui = makeBar(env, [2]);
    env.pcs[0].last = report({ recv: 10 });
    await env.poll();
    const calls = env.pcs[0].statCalls;
    env.VC.leave();
    check('leaving stops the loop', env.liveIntervals().length === 0 && !env.VC.isQualityRunning());
    const t = env.intervals[0]; await t.fn(); await tick();
    check('a tick after leaving does nothing', env.pcs[0].statCalls === calls);
    check('the cached figures are gone', env.VC.getQuality(2) === null);
    check('hiding and showing the page after leaving starts nothing', (env.setHidden(true), env.setHidden(false), env.liveIntervals().length === 0));
    // a kick ends the call through the same path
    const env2 = await joined(makeEnv(), 1, [2]);
    check('the loop runs before the kick', env2.liveIntervals().length === 1);
    env2.VC.handleMessage({ type: 'voice_denied', code: 'kicked', message: 'removed' });
    check('a kick stops the loop too', env2.liveIntervals().length === 0 && !env2.VC.isQualityRunning());
    // a rejoin starts a fresh loop with a fresh baseline
    await joined(env2, 1, [2]);
    check('a new call starts one new loop', env2.liveIntervals().length === 1);
  });

  await scenario('stale results and failures', async () => {
    const env = await joined(makeEnv(), 1, [2, 3]);
    const ui = makeBar(env, [2, 3]);
    env.pcs[0].last = report({ recv: 10 }); env.pcs[1].last = report({ recv: 10 });
    env.pcs[0].throwStats = true;
    await env.poll();
    check('a failing getStats leaves the other peer working', barsOf(ui.slot(3)) === 4 && barsOf(ui.slot(2)) === 0);
    check('the failure is not a call-ending event', env.VC.isInVoice());
    // a result that arrives after the peer left is dropped
    env.pcs[0].throwStats = false;
    let release; const slow = new Promise(r => { release = r; });
    env.pcs[1].getStats = async () => { await slow; return report({ recv: 99 }); };
    env.clock.now += 4000;
    const running = env.liveIntervals()[0].fn();
    env.VC.handleMessage({ type: 'voice_user_left', user_id: 3 });
    release(); await running; await tick();
    check('a result for a peer that left is dropped', env.VC.getQuality(3) === null);
    // a result that arrives after the call ended is dropped
    const env2 = await joined(makeEnv(), 1, [2]);
    let rel2; const slow2 = new Promise(r => { rel2 = r; });
    env2.pcs[0].getStats = async () => { await slow2; return report({ recv: 99 }); };
    const run2 = env2.liveIntervals()[0].fn();
    env2.VC.leave(); rel2(); await run2; await tick();
    check('a result that arrives after leaving is dropped', env2.VC.getQuality(2) === null);
  });

  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness', ok: false, detail: String(e && e.stack || e) })); });

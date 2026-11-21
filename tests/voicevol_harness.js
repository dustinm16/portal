// Runs static/js/voice.js under Node against small fakes: AudioContext with
// GainNodes, <audio> elements, a DOM tree with events, RTCPeerConnection,
// WebSocket and localStorage. Used by tests/test_voicevol.py and
// tools/smoke_checks/check_voicevol.py.
//
// usage: node voicevol_harness.js <path to voice.js>
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
  addEventListener(t, fn) { (this.handlers[t] = this.handlers[t] || []).push(fn); }
  removeEventListener(t, fn) { this.handlers[t] = (this.handlers[t] || []).filter(h => h !== fn); }
}

// ---- fake Web Audio, WebRTC, socket, storage ----------------------------------
function makeEnv(opts) {
  opts = opts || {};
  const doc = new Doc();
  doc.volumeLocked = !!opts.volumeLocked;
  const storage = opts.storage || {};
  const ctxs = [];
  const pcs = [];
  const sent = [];
  const timers = [];
  class Node { constructor(kind, ctx) { this.kind = kind; this.ctx = ctx; this.out = null; this.disconnected = false; }
    connect(n) { this.out = n; } disconnect() { this.disconnected = true; } }
  class FakeAudioContext {
    constructor() {
      if (opts.audioThrows) throw new Error('no audio');
      this.state = opts.ctxState || 'running'; this.nodes = []; this.closed = false; this.onstatechange = null;
      this.destination = new Node('destination', this); ctxs.push(this);
    }
    createMediaStreamSource(stream) {
      if (opts.sourceThrows) throw new Error('InvalidStateError');
      const n = new Node('source', this); n.stream = stream; this.nodes.push(n); return n;
    }
    createGain() { const n = new Node('gain', this); n.gain = { value: 1 }; this.nodes.push(n); return n; }
    createAnalyser() { return { fftSize: 0, getFloatTimeDomainData() {} }; }
    resume() { if (opts.resumeBlocked) return new Promise(() => {}); this.state = 'running'; if (this.onstatechange) this.onstatechange(); return Promise.resolve(); }
    close() { this.closed = true; this.state = 'closed'; return Promise.resolve(); }
  }
  class FakePC {
    constructor() { this.signalingState = 'stable'; this.connectionState = 'new'; this.closed = false; pcs.push(this); }
    addTrack() { return {}; } close() { this.closed = true; }
    async createOffer() { return { type: 'offer', sdp: 'o' }; } async setLocalDescription() {}
    restartIce() {}
  }
  const ws = { readyState: 1, send(m) { sent.push(m); }, addEventListener() {} };
  const localStorage = {
    getItem(k) { if (opts.storageThrows) throw new Error('denied'); return k in storage ? storage[k] : null; },
    setItem(k, v) { if (opts.storageThrows) throw new Error('denied'); storage[k] = String(v); },
    removeItem(k) { if (opts.storageThrows) throw new Error('denied'); delete storage[k]; },
  };
  const win = { innerWidth: 1000, innerHeight: 800, addEventListener() {} };
  if (!opts.noAudio) win.AudioContext = FakeAudioContext;
  const sandbox = {
    window: win, document: doc, localStorage, console: { warn() {}, error() {}, log() {} },
    navigator: { userAgent: opts.ua || 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120', platform: opts.platform || 'Linux x86_64',
      maxTouchPoints: opts.touch || 0,
      mediaDevices: { getUserMedia: async () => ({ getTracks: () => [{ stop() {} }], getAudioTracks: () => [{ enabled: true, stop() {} }] }) } },
    WebSocket: { OPEN: 1 }, RTCPeerConnection: FakePC, RTCSessionDescription: function (d) { return d; },
    RTCIceCandidate: function (d) { return d; }, fetch: async () => ({ ok: false }),
    setTimeout(fn, ms) { const t = { fn, ms, id: timers.length + 1, live: true }; timers.push(t); return t.id; },
    clearTimeout(id) { const t = timers.find(x => x.id === id); if (t) t.live = false; },
    setInterval() { return 0; }, clearInterval() {},
    Float32Array, Promise, JSON, Math, Number, Date, Map, Set, Object, Array, String, Error, Symbol,
  };
  win.window = win;
  sandbox.window.document = doc;
  vm.createContext(sandbox);
  storage['voice_prefs'] = JSON.stringify({ mode: opts.mode || 'ptt' });
  vm.runInContext(SRC + '\n;globalThis.__VC = VoiceChat;', sandbox);
  const VC = sandbox.__VC;
  const env = { VC, doc, ctxs, pcs, sent, storage, timers, ws, sandbox };
  env.runTimers = () => { timers.filter(t => t.live).forEach(t => { t.live = false; t.fn(); }); };
  return env;
}

const tick = () => new Promise(r => setImmediate(r));
async function joined(env, myId, peerIds, extra) {
  const { VC, ws } = env;
  VC.init(ws, (extra && extra.onState) || null, null, myId);
  await VC.join();
  const users = [myId].concat(peerIds).map(id => ({ user_id: id, username: 'u' + id, muted: false, deafened: false, speaking: false }));
  VC.handleMessage({ type: 'voice_state', channel: 'general', resume_token: 'tok', users });
  await tick(); await tick();
  return env;
}
function giveAudio(env, idx, tag) {
  const stream = { id: tag || ('s' + idx) };
  const track = { kind: 'audio' };
  env.pcs[idx].__t = track;
  env.pcs[idx].ontrack({ track, streams: [stream] });
  return stream;
}
const audioEl = (env, uid) => env.doc.getElementById('voice-audio-' + uid);
// the gain node feeding the output for the element that belongs to a peer
function gainOf(env, uid) {
  const el = audioEl(env, uid); if (!el) return null;
  const src = env.ctxs[0].nodes.filter(n => n.kind === 'source' && n.stream === el.srcObject && !n.disconnected).pop();
  return src ? src.out : null;
}
const approx = (a, b) => Math.abs(a - b) < 1e-9;

async function scenario(name, fn) {
  try { await fn(); } catch (e) { check(name + ' (no exception)', false, e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e); }
}

(async () => {
  // ---- three-person call: 40% on one friend, local mute on another -------------
  await scenario('three-person call', async () => {
    const env = await joined(makeEnv(), 1, [2, 3, 4]);
    [2, 3, 4].forEach((u, i) => giveAudio(env, i));
    const { VC } = env;
    check('shared playback context is created once', env.ctxs.length === 1, env.ctxs.length);
    check('every remote element stays attached and muted (Chromium needs it)',
      [2, 3, 4].every(u => audioEl(env, u) && audioEl(env, u).isConnected && audioEl(env, u).muted === true));
    check('every peer starts at full gain', [2, 3, 4].every(u => approx(gainOf(env, u).gain.value, 1)));
    check('slider ceiling is 200 with Web Audio', VC.getMaxVolume() === 200);
    VC.setPeerVolume(2, 40);
    VC.setPeerMuted(3, true);
    check('40% changes only that peer', approx(gainOf(env, 2).gain.value, 0.4) && approx(gainOf(env, 4).gain.value, 1));
    check('local mute silences only that peer', gainOf(env, 3).gain.value === 0 && approx(gainOf(env, 4).gain.value, 1));
    VC.setPeerVolume(4, 200);
    check('200% is allowed', approx(gainOf(env, 4).gain.value, 2));
    VC.setPeerVolume(4, 900);
    check('values above the ceiling are clamped', approx(gainOf(env, 4).gain.value, 2) && VC.getPeerPref(4).volume === 200);
    VC.setPeerVolume(4, 100);
    VC.toggleDeafen();
    check('deafen silences everyone', [2, 3, 4].every(u => gainOf(env, u).gain.value === 0));
    check('deafen keeps the elements muted (no double audio)', [2, 3, 4].every(u => audioEl(env, u).muted === true));
    VC.setPeerVolume(2, 80);
    check('a volume change while deafened stays silent', gainOf(env, 2).gain.value === 0);
    VC.toggleDeafen();
    check('undeafen restores each peer own setting',
      approx(gainOf(env, 2).gain.value, 0.8) && gainOf(env, 3).gain.value === 0 && approx(gainOf(env, 4).gain.value, 1));
    VC.setPeerMuted(3, false);
    check('unmute restores the stored volume', approx(gainOf(env, 3).gain.value, 1));
    check('no frame sent to the server mentions volume or a local mute',
      !env.sent.some(m => /vol|local|gain/i.test(m)), env.sent.join(' '));
    check('the call state offers local_volume and local_muted to the page',
      (() => { VC.setPeerMuted(3, true); const u = VC.getState().users.find(x => x.user_id === 3); return u.local_muted === true && VC.getState().users.find(x => x.user_id === 2).local_volume === 80; })());
    check('no other peer is touched by setting yourself', VC.setPeerVolume(1, 10) === false);
    check('an invalid id is refused', VC.setPeerVolume('abc', 10) === false && VC.setPeerVolume(-3, 10) === false);
  });

  // ---- storage: what is written, rejoin and reload ---------------------------------
  await scenario('storage', async () => {
    const env = await joined(makeEnv(), 7, [2, 3]);
    [0, 1].forEach(i => giveAudio(env, i));
    env.VC.setPeerVolume(2, 40); env.VC.setPeerMuted(3, true);
    const keys = Object.keys(env.storage).filter(k => k !== 'voice_prefs' && k !== 'voice_gate_notice_seen');
    check('preferences live under one key per own account', keys.length === 1 && keys[0] === 'voice_peer_prefs_7', keys.join(','));
    const saved = JSON.parse(env.storage[keys[0]]);
    check('only peers with a non-default setting are stored', Object.keys(saved).sort().join() === '2,3' && saved[2].vol === 40 && saved[3].muted === true, JSON.stringify(saved));
    check('nothing is stored under the peers name', !/u2|u3/.test(JSON.stringify(env.storage)));
    // rejoin in the same page
    env.VC.leave();
    check('leaving closes the playback context and removes the elements',
      env.ctxs[0].closed && !audioEl(env, 2) && !audioEl(env, 3));
    env.pcs.length = 0;
    await env.VC.join();
    env.VC.handleMessage({ type: 'voice_state', channel: 'general', resume_token: 't2',
      users: [7, 2, 3].map(id => ({ user_id: id, username: 'u' + id })) });
    await tick(); await tick();
    giveAudio(env, 0); giveAudio(env, 1);
    check('settings survive a rejoin (new context)', env.ctxs.length === 2 && approx(env.ctxs[1].nodes.filter(n => n.kind === 'gain')[0].gain.value, 0.4)
      && env.ctxs[1].nodes.filter(n => n.kind === 'gain')[1].gain.value === 0);
    // reload: a new page reads the same storage
    const env2 = await joined(makeEnv({ storage: env.storage }), 7, [2, 3]);
    giveAudio(env2, 0); giveAudio(env2, 1);
    check('settings survive a reload', approx(gainOf(env2, 2).gain.value, 0.4) && gainOf(env2, 3).gain.value === 0);
    // another account on the same browser has its own settings
    const env3 = await joined(makeEnv({ storage: env.storage }), 8, [2, 3]);
    giveAudio(env3, 0); giveAudio(env3, 1);
    check('another account in the same browser starts at defaults', approx(gainOf(env3, 2).gain.value, 1) && approx(gainOf(env3, 3).gain.value, 1));
    // resetting to the defaults removes the entry
    env2.VC.resetPeer(2); env2.VC.setPeerMuted(3, false);
    check('defaults remove the stored entry', !('voice_peer_prefs_7' in env2.storage), JSON.stringify(env2.storage));
  });

  await scenario('bad stored data', async () => {
    const bad = { voice_peer_prefs_5: JSON.stringify({ 2: { vol: 'x', muted: 'yes' }, 3: { vol: 9999, muted: true }, '__proto__': { vol: 1 }, abc: { vol: 5 }, 4: 7, 5: { vol: -20 } }) };
    const env = await joined(makeEnv({ storage: bad }), 5, [2, 3, 4]);
    [0, 1, 2].forEach(i => giveAudio(env, i));
    check('junk stored values fall back to defaults', approx(gainOf(env, 2).gain.value, 1) && approx(gainOf(env, 4).gain.value, 1));
    check('a huge stored value is clamped to 200% and keeps its mute', env.VC.getPeerPref(3).volume === 200 && env.VC.getPeerPref(3).muted === true);
    const env2 = await joined(makeEnv({ storage: { voice_peer_prefs_5: '{not json' } }), 5, [2]);
    giveAudio(env2, 0);
    check('unparseable storage is ignored', approx(gainOf(env2, 2).gain.value, 1));
  });

  await scenario('storage unavailable', async () => {
    const env = await joined(makeEnv({ storageThrows: true }), 5, [2, 3]);
    giveAudio(env, 0); giveAudio(env, 1);
    env.VC.setPeerVolume(2, 40);
    check('settings still apply for the call when storage throws', approx(gainOf(env, 2).gain.value, 0.4));
    check('call works with storage throwing', env.VC.isInVoice());
  });

  // ---- the v1.12.0 resume flow: renegotiated and replaced streams ---------------------
  await scenario('resume', async () => {
    const env = await joined(makeEnv(), 1, [2, 3, 4]);
    const s2 = giveAudio(env, 0), s3 = giveAudio(env, 1); giveAudio(env, 2);
    env.VC.setPeerVolume(2, 40); env.VC.setPeerMuted(3, true);
    const oldGain2 = gainOf(env, 2), oldSrc2 = env.ctxs[0].nodes.filter(n => n.kind === 'source' && n.stream === s2)[0];
    const gain3 = gainOf(env, 3);
    // a renegotiation delivers the same stream again: nothing is rebuilt
    const before = env.ctxs[0].nodes.length;
    env.pcs[1].ontrack({ track: env.pcs[1].__t || { kind: 'audio' }, streams: [s3] });
    check('the same stream again does not stack nodes', env.ctxs[0].nodes.length <= before + 2 && approx(gain3.gain.value, 0) , env.ctxs[0].nodes.length);
    // our socket drops and comes back: peer 3 is connected, peer 2 is not
    env.pcs[0].connectionState = 'failed'; env.pcs[1].connectionState = 'connected'; env.pcs[2].connectionState = 'connected';
    env.VC.handleMessage({ type: 'voice_state', channel: 'general', resumed: true, resume_token: 'tok',
      users: [1, 2, 3, 4].map(id => ({ user_id: id, username: 'u' + id })) });
    await tick(); await tick();
    check('only the peer that was not connected is replaced', env.pcs.length === 4 && env.pcs[0].closed && !env.pcs[1].closed && !env.pcs[2].closed, env.pcs.length);
    check('the old peer nodes are disconnected and the element is gone', oldGain2.disconnected && oldSrc2.disconnected && !audioEl(env, 2));
    const s2b = giveAudio(env, 3, 's2-new');
    const g = gainOf(env, 2);
    check('the replaced stream gets a gain node with the stored 40%', g && g !== oldGain2 && approx(g.gain.value, 0.4) && audioEl(env, 2).muted === true);
    check('the other peers keep their gain and setting', !gain3.disconnected && gain3.gain.value === 0 && approx(gainOf(env, 4).gain.value, 1));
    env.VC.toggleDeafen();
    check('deafen also reaches the re-attached stream', g.gain.value === 0 && gain3.gain.value === 0);
    env.VC.toggleDeafen();
    check('undeafen after a resume restores the setting', approx(g.gain.value, 0.4));
    // peer leaves
    const g4 = gainOf(env, 4);
    env.VC.handleMessage({ type: 'voice_user_left', user_id: 4 });
    check('a peer that leaves loses its gain node and element', g4.disconnected && !audioEl(env, 4));
    // the preference stays for a later join of that user
    env.VC.setPeerVolume(4, 60);
    env.VC.handleMessage({ type: 'voice_user_joined', user_id: 4, username: 'u4' });
    env.VC.handleMessage({ type: 'voice_signal', from_user_id: 4, signal: { type: 'offer', sdp: 'x', fresh: true } });
    await tick(); await tick();
    const pc4 = env.pcs[env.pcs.length - 1];
    pc4.ontrack({ track: { kind: 'audio' }, streams: [{ id: 'again' }] });
    check('a user who comes back gets the stored setting', approx(gainOf(env, 4).gain.value, 0.6));
    env.VC.leave();
    check('leave disconnects every node and closes the context',
      env.ctxs[0].nodes.every(n => n.disconnected) && env.ctxs[0].closed);
  });

  // ---- a context that is not running, or a source that fails -------------------------------
  await scenario('suspended context', async () => {
    const env = makeEnv({ ctxState: 'suspended', resumeBlocked: true });  // the browser does not allow playback yet
    await joined(env, 1, [2]);
    const ctx = env.ctxs[0];
    giveAudio(env, 0);
    check('while the context is not running the element plays itself',
      audioEl(env, 2).muted === false && audioEl(env, 2).volume === 1 && gainOf(env, 2).gain.value === 0);
    env.VC.setPeerVolume(2, 40);
    check('element volume carries the setting meanwhile', approx(audioEl(env, 2).volume, 0.4));
    ctx.state = 'running'; ctx.onstatechange();
    check('once running, Web Audio takes over and the element is muted', audioEl(env, 2).muted === true && approx(gainOf(env, 2).gain.value, 0.4));
  });
  await scenario('source fails', async () => {
    const env = await joined(makeEnv({ sourceThrows: true }), 1, [2]);
    giveAudio(env, 0);
    env.VC.setPeerVolume(2, 40);
    check('if Web Audio refuses the stream the element still plays at the setting',
      audioEl(env, 2).muted === false && approx(audioEl(env, 2).volume, 0.4));
  });
  await scenario('no AudioContext', async () => {
    const env = await joined(makeEnv({ noAudio: true }), 1, [2]);
    giveAudio(env, 0);
    check('without AudioContext the ceiling is 100% and audio plays', env.VC.getMaxVolume() === 100 && audioEl(env, 2).muted === false);
    env.VC.setPeerVolume(2, 40);
    check('an element that takes a volume gets it, and no "ignored" note', approx(audioEl(env, 2).volume, 0.4)
      && (env.VC.openUserMenu(2, 'u2', null, { x: 1, y: 1 }), /capped at 100%/.test(env.doc.querySelector('.voice-user-menu').textContent)
      && !/does not allow/.test(env.doc.querySelector('.voice-user-menu').textContent)));
  });

  // ---- iPhone: element volume only, capped at 100% ----------------------------------------------
  for (const [label, o] of [['iPhone', { ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148' }],
                            ['iPad as Mac', { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15', platform: 'MacIntel', touch: 5 }]]) {
    await scenario(label, async () => {
      const store = { voice_peer_prefs_1: JSON.stringify({ 2: { vol: 150, muted: false } }) };
      const env = await joined(makeEnv(Object.assign({ storage: store, volumeLocked: true }, o)), 1, [2, 3]);
      giveAudio(env, 0); giveAudio(env, 1);
      const { VC } = env;
      check(label + ': no Web Audio context is created', env.ctxs.length === 0, env.ctxs.length);
      check(label + ': the slider caps at 100%', VC.getMaxVolume() === 100);
      check(label + ': audio plays through the element', audioEl(env, 2).muted === false && audioEl(env, 3).muted === false);
      check(label + ': a stored 150% plays at 100% and shows 100%', audioEl(env, 2).volume === 1 && VC.getPeerPref(2).volume === 100);
      VC.setPeerVolume(3, 150);
      check(label + ': setting 150% is refused down to 100%', VC.getPeerPref(3).volume === 100 && audioEl(env, 3).volume === 1);
      VC.setPeerVolume(3, 40);
      check(label + ': 40% is stored; the element keeps reading 1 (Safari ignores volume) and mute still works',
        VC.getPeerPref(3).volume === 40 && audioEl(env, 3).volume === 1);
      VC.setPeerMuted(2, true);
      check(label + ': local mute mutes only that element', audioEl(env, 2).muted === true && audioEl(env, 3).muted === false);
      VC.toggleDeafen();
      check(label + ': deafen mutes every element', audioEl(env, 2).muted && audioEl(env, 3).muted);
      VC.toggleDeafen();
      check(label + ': undeafen restores them', audioEl(env, 2).muted === true && audioEl(env, 3).muted === false && audioEl(env, 3).volume === 1);
      check(label + ': the popover says volume below 100% is not available and points to mute', (() => {
        VC.openUserMenu(3, 'u3', null, { x: 5, y: 5 });
        return /does not allow volume changes below 100%/.test(env.doc.querySelector('.voice-user-menu').textContent)
          && /Use Mute for me/.test(env.doc.querySelector('.voice-user-menu').textContent);
      })());
      VC.closeUserMenu();
    });
  }

  // ---- the popover ------------------------------------------------------------------------------------
  await scenario('popover', async () => {
    const env = await joined(makeEnv({ mode: 'vad' }), 1, [2, 3]);
    giveAudio(env, 0); giveAudio(env, 1);
    const { VC, doc } = env;
    const bar = doc.createElement('div'); doc.body.appendChild(bar);
    const render = (extra) => {
      bar.textContent = '';
      for (const uid of [1, 2, 3, 99]) {
        const t = doc.createElement('span'); t.className = 'tile';
        t.setAttribute('data-voice-uid', String(uid)); t.tabIndex = 0; t.textContent = 'user ' + uid; bar.appendChild(t);
      }
      const masked = doc.createElement('span'); masked.className = 'tile'; masked.textContent = 'Anonymous'; bar.appendChild(masked);
      const bad = doc.createElement('span'); bad.className = 'tile'; bad.setAttribute('data-voice-uid', '2abc'); bar.appendChild(bad);
    };
    render();
    const NAME = '<img src=x onerror=alert(1)> "quoted"';
    check('the popover stylesheet does not exist before wiring', !doc.getElementById('voice-user-menu-style'));
    VC.attachUserMenu(bar, { selector: '.tile', nameFor: () => NAME, enterOpens: true });
    check('wiring injects the stylesheet with the no-callout rule before any open',
      !!doc.getElementById('voice-user-menu-style') && /touch-callout:none/.test(doc.getElementById('voice-user-menu-style').textContent));
    VC.attachUserMenu(bar, { selector: '.tile', nameFor: () => 'second attach is ignored' });
    const tile = (uid) => bar.children.find(c => c.getAttribute('data-voice-uid') === String(uid));
    const menu = () => doc.querySelector('.voice-user-menu');

    let e = tile(1).fire('contextmenu', { clientX: 30, clientY: 40 });
    check('no popover for yourself, the browser menu is left alone', !menu() && !e.defaultPrevented);
    e = tile(99).fire('contextmenu', {});
    check('no popover for someone who is not in the call', !menu() && !e.defaultPrevented);
    e = bar.children[4].fire('contextmenu', {});
    check('a tile without an id (masked anonymous entry) opens nothing', !menu() && !e.defaultPrevented);
    e = bar.children[5].fire('contextmenu', {});
    check('a malformed id opens nothing', !menu());

    e = tile(2).fire('contextmenu', { clientX: 30, clientY: 40 });
    check('right-click opens the popover and stops the browser menu', !!menu() && e.defaultPrevented);
    const root = menu();
    check('the popover lives under body, outside the tile container', root.parent === doc.body && !bar.contains(root));
    check('the name is shown as plain text, not markup', root.children[0].textContent === NAME && root.children.every(c => c.tag !== 'IMG'));
    check('the popover is a labelled dialog', root.getAttribute('role') === 'dialog' && /Volume for/.test(root.getAttribute('aria-label')));
    check('the popover is placed at the pointer', root.style.left === '30px' && root.style.top === '40px', root.style.left + ',' + root.style.top);
    const slider = root.querySelector('input'); const mute = root.querySelector('.vum-mute');
    check('focus goes to the slider', doc.activeElement === slider);
    check('the slider runs 0 to 200', slider.getAttribute('max') === undefined || slider.max === '200');

    slider.value = '40'; slider.fire('input');
    check('moving the slider changes that peer only', approx(gainOf(env, 2).gain.value, 0.4) && approx(gainOf(env, 3).gain.value, 1));
    mute.fire('click');
    check('Mute for me mutes that peer', gainOf(env, 2).gain.value === 0 && mute.textContent === 'Unmute for me' && mute.getAttribute('aria-pressed') === 'true');
    render();   // a voice event re-renders the tiles while the popover is open
    check('a re-render of the tiles leaves the popover open', menu() === root && root.isConnected);
    root.querySelector('.vum-reset').fire('click');
    check('Reset returns to 100% and unmuted', approx(gainOf(env, 2).gain.value, 1) && !('voice_peer_prefs_1' in env.storage));

    // Tab stays inside the popover
    doc.activeElement = root.querySelector('.vum-close');
    const tab = { key: 'Tab', shiftKey: false }; (doc.handlers.keydown || []).forEach(h => h(Object.assign({ target: { tagName: 'DIV' }, preventDefault() {}, stopPropagation() {} }, tab)));
    check('Tab wraps to the first control', doc.activeElement === slider);

    // Esc closes and returns focus to the (re-rendered) tile
    const esc = { key: 'Escape', defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, stopPropagation() {} };
    (doc.handlers.keydown || []).slice().forEach(h => h(esc));
    check('Esc closes the popover', !menu() && esc.defaultPrevented);
    check('focus returns to the re-rendered tile of that peer', doc.activeElement === tile(2));
    check('closing removes the document listeners', (doc.handlers.keydown || []).length === 0 && (doc.handlers.pointerdown || []).length === 0);

    // keyboard routes
    tile(2).focus();
    tile(2).fire('keydown', { key: 'Enter' });
    check('Enter on a focused tile opens it', !!menu());
    VC.closeUserMenu();
    tile(2).fire('keydown', { key: ' ' });
    check('Space is left for push-to-talk and does not open it', !menu());
    tile(3).fire('keydown', { key: 'ContextMenu' });
    check('the context-menu key opens it', !!menu() && menu().getAttribute('aria-label').indexOf('Volume') === 0);
    VC.closeUserMenu();
    tile(3).fire('keydown', { key: 'F10', shiftKey: true });
    check('Shift+F10 opens it', !!menu());
    check('keyboard opening places it under the tile', menu().style.left === '10px' && menu().style.top === '24px', menu().style.left + ',' + menu().style.top);
    // outside click closes
    doc.body.fire('pointerdown', {});
    check('a pointer press outside closes it', !menu());
    // opening a second one replaces the first
    tile(2).fire('contextmenu', { clientX: 1, clientY: 1 }); tile(3).fire('contextmenu', { clientX: 1, clientY: 1 });
    check('only one popover is open at a time', doc.body.children.filter(c => c.className === 'voice-user-menu').length === 1);
    // the peer leaves: the popover closes
    env.VC.handleMessage({ type: 'voice_user_left', user_id: 3 });
    check('the popover closes when its peer leaves', !menu());
    // keepFocus helper
    tile(2).focus();
    VC.renderKeepingFocus(bar, () => render());
    check('re-rendering keeps keyboard focus on the same tile', doc.activeElement === tile(2));

    // long press
    tile(2).fire('touchstart', { touches: [{ clientX: 50, clientY: 60 }] });
    check('a touch starts a 500 ms timer', env.timers.some(t => t.live && t.ms === 500));
    env.runTimers();
    check('a long press opens the popover at the finger', !!menu() && menu().style.left === '50px' && menu().style.top === '60px');
    tile(2).fire('touchend', {});
    const click = tile(2).fire('click', {});
    check('the click after a long press is swallowed (no mention is inserted)', click.stopped && click.defaultPrevented);
    const click2 = tile(2).fire('click', {});
    check('later clicks are not swallowed', !click2.stopped);
    VC.closeUserMenu();
    tile(2).fire('touchstart', { touches: [{ clientX: 50, clientY: 60 }] });
    tile(2).fire('touchmove', { touches: [{ clientX: 50, clientY: 120 }] });
    env.runTimers();
    check('moving the finger cancels the long press', !menu());
    tile(2).fire('touchstart', { touches: [{ clientX: 50, clientY: 60 }] });
    tile(2).fire('touchend', {});
    env.runTimers();
    check('lifting early cancels the long press', !menu());

    // leaving the call closes it
    tile(2).fire('contextmenu', { clientX: 1, clientY: 1 });
    VC.leave();
    check('leaving the call closes the popover', !menu());
    e = tile(2).fire('contextmenu', { clientX: 1, clientY: 1 });
    check('outside a call nothing opens', !menu() && !e.defaultPrevented);
  });

  await scenario('push-to-talk keys', async () => {
    // PTT mode: Space transmits, except on a button and anywhere inside the volume popover
    const env = await joined(makeEnv({ mode: 'ptt' }), 1, [2]);
    giveAudio(env, 0);
    const { VC, doc, ws } = env;
    const press = (target, code) => (doc.handlers.keydown || []).slice().forEach(h => h({ code: code || 'Space', target, preventDefault() {}, stopPropagation() {} }));
    const release = (target) => (doc.handlers.keyup || []).slice().forEach(h => h({ code: 'Space', target, preventDefault() {}, stopPropagation() {} }));
    const speaking = () => VC.getState().speaking === true || env.sent.some(m => m.indexOf('"voice_speaking"') >= 0 && m.indexOf('true') >= 0);
    const sentSpeaking = () => env.sent.filter(m => m.indexOf('voice_speaking') >= 0).length;
    check('push-to-talk listeners are installed in PTT mode', (doc.handlers.keydown || []).length >= 1);
    press({ tagName: 'BUTTON' });
    check('Space on a button does not transmit', sentSpeaking() === 0);
    press({ tagName: 'INPUT' }); press({ tagName: 'TEXTAREA' });
    check('Space in a text field does not transmit', sentSpeaking() === 0);
    // inside the popover (a real node under .voice-user-menu, not a button)
    const bar = doc.createElement('div'); doc.body.appendChild(bar);
    const tile = doc.createElement('span'); tile.className = 'tile'; tile.setAttribute('data-voice-uid', '2'); bar.appendChild(tile);
    VC.openUserMenu(2, 'peer', tile, { x: 5, y: 5 });
    const root = doc.querySelector('.voice-user-menu');
    check('the popover is open', !!root);
    const slider = root.querySelector('input');
    press(slider);
    check('Space on the slider inside the popover does not transmit', sentSpeaking() === 0);
    press(root.querySelector('.vum-title'));
    check('Space on any element inside the popover does not transmit', sentSpeaking() === 0);
    press({ tagName: 'DIV', closest(sel) { return sel === '.voice-user-menu' ? root : null; } });
    check('Space on an element that closest() places in the popover does not transmit', sentSpeaking() === 0);
    VC.closeUserMenu();
    press({ tagName: 'BODY', closest() { return null; } });
    check('Space elsewhere on the page still transmits', sentSpeaking() === 1 && speaking());
    release({ tagName: 'BODY' });
    check('releasing stops transmitting', sentSpeaking() === 2);
    press({ tagName: 'BODY', closest() { return null; } }, 'KeyQ');
    check('another key does not transmit', sentSpeaking() === 2);
  });

  await scenario('reentrancy', async () => {
    // a second join after a failed microphone does not leave a context open
    const env = makeEnv();
    env.sandbox.navigator.mediaDevices.getUserMedia = async () => { throw new Error('denied'); };
    env.VC.init(env.ws, null, null, 1);
    await env.VC.join();
    check('a refused microphone closes the playback context again', env.ctxs.length === 1 && env.ctxs[0].closed && !env.VC.isInVoice());
  });

  // ---- 1.20.0: moderation (server mute, lock, kick, the popover) -------------------
  await scenario('moderation', async () => {
    const track = { enabled: true, stop() {} };
    const env = makeEnv({ mode: 'vad' });
    env.sandbox.navigator.mediaDevices.getUserMedia = async () => ({ getTracks: () => [track], getAudioTracks: () => [track] });
    let last = null;
    env.VC.init(env.ws, (st) => { last = st; }, null, 1);
    await env.VC.join();
    const users = [1, 2, 3].map(id => ({ user_id: id, username: 'u' + id, muted: false, deafened: false, speaking: false }));
    env.VC.handleMessage({ type: 'voice_state', channel: 'general', resume_token: 'tok', users, locked: false, can_moderate: true, room_cap: 8 });
    await tick(); await tick();
    const { VC } = env;
    const sentTypes = () => env.sent.map(m => JSON.parse(m).type);
    check('the state carries the moderator right, the lock and the cap',
      VC.getState().canModerate === true && VC.getState().locked === false && VC.getState().roomCap === 8);
    check('the microphone is open before a server mute', track.enabled === true);
    VC.handleMessage({ type: 'voice_server_mute_changed', user_id: 1, server_muted: true });
    check('a server mute of me closes the microphone and shows it',
      track.enabled === false && VC.getState().serverMuted === true && last.serverMuted === true);
    const before = env.sent.length;
    VC.toggleMute();
    check('I cannot unmute myself while server muted', VC.getState().muted === false && env.sent.length === before && track.enabled === false);
    VC.handleMessage({ type: 'voice_server_mute_changed', user_id: 2, server_muted: true });
    check('everyone sees the server-muted mark', VC.getState().users.find(u => u.user_id === 2).server_muted === true
      && VC.getState().users.find(u => u.user_id === 3).server_muted === false);
    VC.handleMessage({ type: 'voice_server_mute_changed', user_id: 1, server_muted: false });
    check('lifting it opens the microphone again', track.enabled === true && VC.getState().serverMuted === false);
    VC.handleMessage({ type: 'voice_room_lock_changed', locked: true });
    check('the lock state follows the server', VC.getState().locked === true);
    env.sent.length = 0;
    check('kick, server mute and lock send their frames', VC.kick(3) && VC.serverMute(2, false) && VC.serverMute(3, true) && VC.setRoomLocked(false)
      && sentTypes().join() === 'voice_kick,voice_server_unmute,voice_server_mute,voice_unlock_room'
      && JSON.parse(env.sent[0]).target_user_id === 3, env.sent.join(' '));
    check('an invalid id is refused', VC.kick('abc') === false && VC.serverMute(-4, true) === false);
    VC.openUserMenu(2, 'u2', null, { x: 1, y: 1 });
    let menu = env.doc.querySelector('.voice-user-menu');
    check('a moderator sees Kick and a server mute action in the popover with the help text',
      !!menu.querySelector('.vum-kick') && !!menu.querySelector('.vum-server-mute')
      && /cooperative/.test(menu.textContent) && /enforced against normal clients only/.test(menu.textContent));
    check('the action says Server unmute for a muted member', menu.querySelector('.vum-server-mute').textContent === 'Server unmute');
    env.sent.length = 0;
    menu.querySelector('.vum-kick').fire('click');
    check('Kick in the popover sends voice_kick for that member and closes it',
      sentTypes().join() === 'voice_kick' && JSON.parse(env.sent[0]).target_user_id === 2 && !env.doc.querySelector('.voice-user-menu'));
    VC.leave();

    // a member without the right
    const env2 = makeEnv({ mode: 'vad' });
    env2.VC.init(env2.ws, null, null, 1);
    await env2.VC.join();
    env2.VC.handleMessage({ type: 'voice_state', channel: 'general', resume_token: 'tok', users, locked: true, can_moderate: false });
    await tick(); await tick();
    env2.sent.length = 0;
    check('without the right no moderation frame is sent', !env2.VC.kick(2) && !env2.VC.serverMute(2, true) && !env2.VC.setRoomLocked(true) && env2.sent.length === 0);
    env2.VC.openUserMenu(2, 'u2', null, { x: 1, y: 1 });
    const m2 = env2.doc.querySelector('.voice-user-menu');
    check('the popover of an ordinary member has no Kick and no server mute', !m2.querySelector('.vum-kick') && !m2.querySelector('.vum-server-mute'));
    env2.VC.handleMessage({ type: 'voice_denied', code: 'kicked', message: 'A moderator removed you from this voice chat.' });
    check('a kick ends the call on this client', !env2.VC.isInVoice() && env2.VC.getState().canModerate === false && env2.VC.getState().locked === false);
  });

  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness', ok: false, detail: String(e && e.stack || e) })); });

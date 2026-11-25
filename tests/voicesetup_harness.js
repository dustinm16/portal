// Runs static/js/voice.js under Node against fakes made for the voice setup
// panel: microphones with a settable level (a disabled track delivers silence,
// as in a browser), tracks with clone() and stop(), a getUserMedia that records
// its constraints and can be held, peer connections with senders and
// replaceTrack, an AudioContext with analysers and gain nodes (with or without
// setSinkId), devicechange events, a clock and timers that the test advances,
// and a localStorage. Used by tests/test_voicesetup.py and
// tools/smoke_checks/check_voicesetup.py.
//
// usage: node voicesetup_harness.js <path to voice.js>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const SRC = fs.readFileSync(process.argv[2], 'utf8');
const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) });
}

// ---- fake DOM (just what voice.js touches outside the popover) ---------------
class El {
  constructor(tag, doc) {
    this.tag = tag.toUpperCase(); this.doc = doc; this.children = []; this.parent = null;
    this.attrs = {}; this.style = {}; this.muted = false; this.volume = 1; this.srcObject = null;
    this.id = ''; this.className = ''; this.handlers = {};
    if (tag === 'audio' && doc.elSink) {
      this.sinkCalls = [];
      this.setSinkId = (id) => { this.sinkCalls.push(id); return Promise.resolve(); };
    }
  }
  appendChild(c) { if (c.parent) c.remove(); c.parent = this; this.children.push(c); return c; }
  remove() { if (this.parent) { this.parent.children = this.parent.children.filter(x => x !== this); this.parent = null; } }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(t, fn) { (this.handlers[t] = this.handlers[t] || []).push(fn); }
  querySelector(sel) {
    for (const c of this.children) {
      if (sel[0] === '#' && c.id === sel.slice(1)) return c;
      const r = c.querySelector(sel); if (r) return r;
    }
    return null;
  }
}
class Doc {
  constructor() {
    this.handlers = {}; this.activeElement = null; this.elSink = false;
    this.documentElement = new El('html', this); this.body = new El('body', this); this.head = new El('head', this);
    this.documentElement.appendChild(this.head); this.documentElement.appendChild(this.body);
  }
  createElement(t) { return new El(t, this); }
  getElementById(id) { return this.documentElement.querySelector('#' + id); }
  addEventListener(t, fn) { (this.handlers[t] = this.handlers[t] || []).push(fn); }
  removeEventListener(t, fn) { this.handlers[t] = (this.handlers[t] || []).filter(h => h !== fn); }
  fire(type, ev) { (this.handlers[type] || []).slice().forEach(h => h(Object.assign({ type, target: { tagName: 'BODY' } }, ev || {}))); }
  listeners(type) { return (this.handlers[type] || []).length; }
}

// ---- environment ---------------------------------------------------------------
function makeEnv(opts) {
  opts = opts || {};
  const doc = new Doc();
  doc.elSink = !!opts.elSink;
  const storage = opts.storage || {};
  if (!('voice_prefs' in storage)) storage.voice_prefs = JSON.stringify({ mode: opts.mode || 'vad' });
  const clock = { t: 1000 };
  const intervals = [], timeouts = [];
  const sent = [], toasts = [], gumCalls = [], opened = [], clones = [], ctxs = [], pcs = [], sinkCalls = [];
  const devs = {
    default: { id: 'default', level: 0 },
    'usb-1': { id: 'usb-1', level: 0 },
    'usb-2': { id: 'usb-2', level: 0 },
  };
  const env = { doc, storage, clock, intervals, timeouts, sent, toasts, gumCalls, opened, clones, ctxs, pcs, sinkCalls, devs,
    holdGum: false, pendingGum: [], ctxState: opts.ctxState || 'running', deviceList: [], deviceWatchers: [], gumError: null,
    liveAtCall: [], holdReplace: false, pendingReplace: [] };

  let trackId = 0;
  class Track {
    constructor(src, isClone) { this.kind = 'audio'; this.enabled = true; this.stopped = false; this.src = src;
      this.onended = null; this.id = ++trackId; this.isClone = !!isClone; }
    stop() { this.stopped = true; }
    clone() {
      if (opts.noClone) throw new Error('no clone');
      const c = new Track(this.src, true); c.parent = this; clones.push(c); return c;
    }
  }
  if (opts.noClone) Track.prototype.clone = undefined;
  class Stream {
    constructor(tracks) { this.tracks = (tracks || []).slice(); }
    getTracks() { return this.tracks.slice(); }
    getAudioTracks() { return this.tracks.filter(t => t.kind === 'audio'); }
    getVideoTracks() { return this.tracks.filter(t => t.kind === 'video'); }
    addTrack(t) { this.tracks.push(t); }
    removeTrack(t) { this.tracks = this.tracks.filter(x => x !== t); }
  }

  class Node {
    constructor(kind, ctx) { this.kind = kind; this.ctx = ctx; this.outs = []; this.disconnected = false; }
    connect(n) { this.outs.push(n); this.disconnected = false; if (n && n.kind === 'analyser') n.input = this; }
    disconnect(n) { if (n) { this.outs = this.outs.filter(o => o !== n); return; } this.outs = []; this.disconnected = true; }
  }
  class FakeAudioContext {
    constructor() {
      if (opts.audioThrows) throw new Error('no audio');
      this.state = env.ctxState; this.closed = false; this.nodes = []; this.sink = undefined; this.onstatechange = null;
      this.destination = new Node('destination', this); ctxs.push(this);
    }
    createMediaStreamSource(stream) { const n = new Node('source', this); n.stream = stream; this.nodes.push(n); return n; }
    createGain() { const n = new Node('gain', this); n.gain = { value: 1 }; this.nodes.push(n); return n; }
    createAnalyser() {
      const a = new Node('analyser', this); a.fftSize = 0; a.input = null;
      a.getFloatTimeDomainData = (arr) => {
        const t = a.input && a.input.stream && a.input.stream.getTracks()[0];
        // a disabled or stopped track delivers silence, as in a browser
        arr.fill(t && !t.stopped && t.enabled ? t.src.level : 0);
      };
      this.nodes.push(a); return a;
    }
    resume() { if (!env.resumeBlocked) this.state = 'running'; return Promise.resolve(); }
    close() { this.closed = true; this.state = 'closed'; return Promise.resolve(); }
  }
  if (opts.ctxSink) {
    FakeAudioContext.prototype.setSinkId = function (id) {
      this.sink = id; sinkCalls.push(['ctx', id]);
      return opts.sinkReject ? Promise.reject({ name: 'NotFoundError' }) : Promise.resolve();
    };
  }

  class FakeSender {
    constructor(track) { this.track = track; this.replaced = []; this.enabledAtReplace = []; }
    replaceTrack(t) {
      this.replaced.push(t); this.enabledAtReplace.push(t.enabled); this.track = t;
      if (env.holdReplace) return new Promise(resolve => { env.pendingReplace.push(resolve); });
      return Promise.resolve();
    }
  }
  class FakePC {
    constructor() { this.signalingState = 'stable'; this.connectionState = 'new'; this.closed = false; this.senders = []; pcs.push(this); }
    addTrack(track) { const s = new FakeSender(track); this.senders.push(s); return s; }
    removeTrack() {}
    close() { this.closed = true; }
    async createOffer() { return { type: 'offer', sdp: 'o' }; }
    async setLocalDescription() {}
    restartIce() {}
  }

  const md = {
    getUserMedia(c) {
      gumCalls.push(c);
      env.liveAtCall.push(opened.filter(t => !t.stopped).length);
      const exact = c.audio && c.audio.deviceId && c.audio.deviceId.exact;
      const make = () => {
        if (env.gumError) throw { name: env.gumError };
        let dev = devs.default;
        if (exact) {
          dev = devs[exact];
          if (!dev || dev.gone) throw { name: 'OverconstrainedError' };
        }
        const t = new Track(dev, false); opened.push(t);
        return new Stream([t]);
      };
      if (env.holdGum) {
        return new Promise((resolve, reject) => {
          env.pendingGum.push({ exact, release() { try { resolve(make()); } catch (e) { reject(e); } } });
        });
      }
      return new Promise((resolve, reject) => { try { resolve(make()); } catch (e) { reject(e); } });
    },
    async enumerateDevices() { return env.deviceList.slice(); },
    addEventListener(t, fn) { if (t === 'devicechange') env.deviceWatchers.push(fn); },
    async getDisplayMedia() {
      const a = new Track({ id: 'screen', level: 0 }, false); const v = new Track({ id: 'screen', level: 0 }, false); v.kind = 'video';
      a.isScreen = true; opened.push(a);
      return new Stream([v, a]);
    },
  };
  if (opts.noEnumerate) delete md.enumerateDevices;

  const ws = { readyState: 1, handlers: {}, send(m) { sent.push(m); }, addEventListener(t, fn) { (this.handlers[t] = this.handlers[t] || []).push(fn); } };
  const storageApi = {
    getItem(k) { if (opts.storageThrows) throw new Error('denied'); return k in storage ? storage[k] : null; },
    setItem(k, v) { if (opts.storageThrows) throw new Error('denied'); storage[k] = String(v); },
    removeItem(k) { if (opts.storageThrows) throw new Error('denied'); delete storage[k]; },
  };
  const Portal = { toast(msg, kind) { toasts.push(msg); } };
  const win = { innerWidth: 1000, innerHeight: 800, addEventListener() {}, Portal };
  if (!opts.noAudio) win.AudioContext = FakeAudioContext;
  win.window = win; win.document = doc;
  const sandbox = {
    window: win, document: doc, localStorage: storageApi, Portal, console: { warn() {}, error() {}, log() {} },
    navigator: { userAgent: opts.ua || 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120', platform: opts.platform || 'Linux x86_64',
      maxTouchPoints: opts.touch || 0, mediaDevices: md },
    WebSocket: { OPEN: 1 }, RTCPeerConnection: FakePC, RTCSessionDescription: function (d) { return d; },
    RTCIceCandidate: function (d) { return d; }, fetch: async () => ({ ok: false }),
    MediaStream: function (tracks) { return new Stream(tracks); },
    Date: { now: () => clock.t },
    setTimeout(fn, ms) { const t = { fn, ms, due: clock.t + (ms || 0), live: true, id: timeouts.length + 1 }; timeouts.push(t); return t.id; },
    clearTimeout(id) { const t = timeouts.find(x => x.id === id); if (t) t.live = false; },
    setInterval(fn, ms) { const t = { fn, ms, next: clock.t + ms, live: true, id: intervals.length + 1 }; intervals.push(t); return t.id; },
    clearInterval(id) { const t = intervals.find(x => x.id === id); if (t) t.live = false; },
    Float32Array, Promise, JSON, Math, Number, Map, Set, Object, Array, String, Error, Symbol, Infinity, isFinite, parseInt,
  };
  if (opts.noMediaStream) delete sandbox.MediaStream;
  if (opts.elSink) sandbox.HTMLMediaElement = function () {};
  if (opts.elSink) sandbox.HTMLMediaElement.prototype.setSinkId = function () {};
  vm.createContext(sandbox);
  vm.runInContext(SRC + '\n;globalThis.__VC = VoiceChat;', sandbox);
  env.VC = sandbox.__VC; env.ws = ws; env.sandbox = sandbox; env.Track = Track;

  env.advance = (ms) => {
    const end = clock.t + ms;
    while (clock.t < end) {
      clock.t += 10;
      for (const iv of intervals) if (iv.live && clock.t >= iv.next) { iv.next += iv.ms; iv.fn(); }
      for (const t of timeouts) if (t.live && clock.t >= t.due) { t.live = false; t.fn(); }
    }
  };
  env.liveHandles = () => opened.filter(t => !t.stopped);
  env.liveClones = () => clones.filter(t => !t.stopped);
  // the 4 s connection-quality loop (voicequality_harness.js tests it) is not a meter or VAD timer
  env.liveIntervals = () => intervals.filter(t => t.live && t.ms !== 4000).length;
  env.liveTimeouts = () => timeouts.filter(t => t.live).length;
  env.types = () => sent.map(m => JSON.parse(m).type);
  env.speaking = () => sent.map(m => JSON.parse(m)).filter(m => m.type === 'voice_speaking').map(m => m.speaking);
  env.mic = () => env.sandbox.__VC && opened.filter(t => !t.stopped && !t.isClone && !t.isScreen).slice(-1)[0];
  env.fireDeviceChange = () => env.deviceWatchers.forEach(f => f());
  env.openCtxs = () => ctxs.filter(c => !c.closed);
  return env;
}

const tick = () => new Promise(r => setImmediate(r));
// let every held replaceTrack finish, however many are queued by then
async function releaseReplaces(env) {
  for (let i = 0; i < 20; i++) {
    await tick();
    const q = env.pendingReplace.splice(0);
    if (!q.length && i > 3) return;
    q.forEach(r => r());
  }
}
async function flush() { for (let i = 0; i < 5; i++) await tick(); }
const LOUD = 0.1;        // -20 dBFS
const QUIET = 0.0005;    // about -66 dBFS
const db = (a) => 20 * Math.log10(a);

async function joined(env, myId, peerIds) {
  const { VC, ws } = env;
  VC.init(ws, null, null, myId);
  await VC.join();
  const users = [myId].concat(peerIds || []).map(id => ({ user_id: id, username: 'u' + id, muted: false, deafened: false, speaking: false }));
  VC.handleMessage({ type: 'voice_state', channel: 'general', resume_token: 'tok', users });
  await flush();
  return env;
}
function giveAudio(env, idx) {
  const stream = { id: 's' + idx }; const track = { kind: 'audio' };
  env.pcs[idx].ontrack({ track, streams: [stream] });
  return stream;
}
async function scenario(name, fn) {
  try { await fn(); } catch (e) { check(name + ' (no exception)', false, e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e); }
}

(async () => {
  // ---- device id: stored, used on the next join, falls back ----------------------
  await scenario('device on join', async () => {
    const env = makeEnv({ mode: 'vad' });
    env.VC.init(env.ws, null, null, 1);
    await env.VC.setInputDevice('usb-1');
    check('choosing a device outside a call opens nothing', env.gumCalls.length === 0);
    check('the choice is stored in localStorage', JSON.parse(env.storage.voice_prefs).inputDeviceId === 'usb-1');
    check('the choice is reported by getPrefs', env.VC.getPrefs().inputDeviceId === 'usb-1');
    await env.VC.join();
    check('the next join asks for exactly that device', env.gumCalls.length === 1 && env.gumCalls[0].audio.deviceId.exact === 'usb-1',
      JSON.stringify(env.gumCalls));
    check('the call keeps the echo, noise and gain settings it always had',
      env.gumCalls[0].audio.echoCancellation === true && env.gumCalls[0].audio.noiseSuppression === true && env.gumCalls[0].audio.autoGainControl === true);
    check('the microphone in the call is that device', env.mic().src.id === 'usb-1');
    env.VC.leave();
    // a different browser session: the stored id is read again
    const env2 = makeEnv({ storage: env.storage });
    env2.VC.init(env2.ws, null, null, 1);
    await env2.VC.join();
    check('after a reload the stored device is used', env2.gumCalls[0].audio.deviceId.exact === 'usb-1');
    // unplugged since it was chosen
    env.devs['usb-1'].gone = true;
    await env.VC.join();
    check('an unplugged device falls back to the default with a second request',
      env.gumCalls.length === 3 && !env.gumCalls[2].audio.deviceId && env.mic().src.id === 'default', JSON.stringify(env.gumCalls.slice(1)));
    check('the member is told', env.toasts.some(t => /not available/.test(t)), env.toasts.join('|'));
    check('the saved choice stays, in case the device comes back', env.VC.getPrefs().inputDeviceId === 'usb-1');
    env.VC.leave();
    // a refused permission is not retried
    const env3 = makeEnv({ storage: { voice_prefs: JSON.stringify({ mode: 'vad', inputDeviceId: 'usb-1' }) } });
    env3.gumError = 'NotAllowedError';
    env3.VC.init(env3.ws, null, null, 1);
    await env3.VC.join();
    check('a refused microphone permission is not retried without the device', env3.gumCalls.length === 1);
    check('and the member is not in the call', env3.VC.isInVoice() === false && !env3.types().includes('voice_join'));
    check('the device id never reaches the server',
      !env.sent.concat(env2.sent, env3.sent).some(m => /usb-1|deviceId|inputDevice/i.test(m)), env.sent.join(' '));
  });

  // ---- stored values are not trusted -----------------------------------------------
  await scenario('stored preferences', async () => {
    const bad = makeEnv({ storage: { voice_prefs: JSON.stringify({ mode: 'weird', pttKey: { a: 1 }, vadThreshold: 'abc', pttDelay: 99999,
      inputDeviceId: 42, outputDeviceId: { x: 1 }, noiseGate: 'yes' }) } });
    bad.VC.init(bad.ws, null, null, 1);
    const p = bad.VC.getPrefs();
    check('junk values fall back to the defaults, the delay is clamped',
      p.mode === 'vad' && p.pttKey === 'Space' && p.vadThreshold === -50 && p.pttDelay === 1000 && p.inputDeviceId === '' && p.outputDeviceId === '' && p.noiseGate === true,
      JSON.stringify(p));
    const neg = makeEnv({ storage: { voice_prefs: JSON.stringify({ vadThreshold: -999, pttDelay: -5 }) } });
    neg.VC.init(neg.ws, null, null, 1);
    check('out-of-range numbers are clamped', neg.VC.getPrefs().vadThreshold === -100 && neg.VC.getPrefs().pttDelay === 0);
    const broken = makeEnv({ storage: { voice_prefs: '{not json' } });
    broken.VC.init(broken.ws, null, null, 1);
    check('unparseable storage keeps the defaults', broken.VC.getPrefs().mode === 'vad' && broken.VC.getPrefs().pttDelay === 0);
    const arr = makeEnv({ storage: { voice_prefs: '[1,2]' } });
    arr.VC.init(arr.ws, null, null, 1);
    check('an array in storage is ignored', arr.VC.getPrefs().mode === 'vad');
    const nostore = makeEnv({ storageThrows: true });
    nostore.VC.init(nostore.ws, null, null, 1);
    check('storage that throws does not break the setters',
      nostore.VC.setPttDelay(200) === true && nostore.VC.getPrefs().pttDelay === 200 && nostore.VC.setVadThreshold(-40) === true);
    check('setters refuse junk', nostore.VC.setPttDelay('x') === false && nostore.VC.setPttDelay(null) === false
      && nostore.VC.setVadThreshold('') === false && nostore.VC.getPrefs().pttDelay === 200 && nostore.VC.getPrefs().vadThreshold === -40);
    check('setters clamp', (nostore.VC.setPttDelay(5000), nostore.VC.getPrefs().pttDelay === 1000)
      && (nostore.VC.setPttDelay(-1), nostore.VC.getPrefs().pttDelay === 0) && (nostore.VC.setVadThreshold(10), nostore.VC.getPrefs().vadThreshold === 0));
  });

  // ---- the VAD gate -------------------------------------------------------------------
  await scenario('vad gate', async () => {
    const env = makeEnv({ mode: 'vad' });
    env.devs.default.level = QUIET;
    await joined(env, 1, [2]);
    const mic = env.mic();
    check('in VAD mode the track sent to peers is closed while nobody speaks', mic.enabled === false);
    check('the analysis reads a clone that stays enabled',
      env.liveClones().length === 1 && env.liveClones()[0].enabled === true && env.liveClones()[0].parent === mic);
    env.advance(500);
    check('silence keeps it closed and says nothing about speaking', mic.enabled === false && !env.speaking().includes(true));
    env.devs.default.level = LOUD;
    env.advance(30);
    check('speech opens the gate', mic.enabled === true);
    check('and the server hears that this member speaks', env.speaking().slice(-1)[0] === true);
    env.devs.default.level = QUIET;
    env.advance(700);
    check('the gate stays open through the hang time (about 750 ms)', mic.enabled === true);
    env.advance(120);
    check('after the hang time it closes again', mic.enabled === false && env.speaking().slice(-1)[0] === false);
    env.VC.setVadThreshold(-30);
    env.devs.default.level = 0.01;       // -40 dBFS
    env.advance(100);
    check('a stricter threshold keeps a -40 dBFS sound out', mic.enabled === false);
    env.VC.setVadThreshold(-50);
    env.advance(40);
    check('a lower threshold lets the same sound in', mic.enabled === true);
    env.devs.default.level = LOUD;
    env.advance(30);
    env.VC.toggleMute();
    check('muting closes the gate at once while the member is loud', mic.enabled === false);
    check('and the speaking state is withdrawn', env.speaking().slice(-1)[0] === false);
    env.advance(100);
    check('a muted member stays closed', mic.enabled === false);
    env.VC.toggleMute();
    check('unmuting does not open it by itself', mic.enabled === false);
    env.advance(30);
    check('it opens again with the next speech', mic.enabled === true);
    env.devs.default.level = QUIET;
    env.VC.setMode('ptt');
    check('switching to PTT closes the track and drops the analysis',
      mic.enabled === false && env.liveClones().length === 0 && env.doc.listeners('keydown') === 1);
    env.VC.setMode('vad');
    check('switching back to VAD starts one analysis again', env.liveClones().length === 1 && env.doc.listeners('keydown') === 0);
    env.VC.leave();
    check('leaving stops the analysis, its clone and its timer',
      env.liveClones().length === 0 && env.liveIntervals() === 0 && env.openCtxs().length === 0, `${env.liveClones().length} ${env.liveIntervals()} ${env.openCtxs().length}`);
    check('every microphone handle is released after leaving', env.liveHandles().length === 0);
  });

  await scenario('vad fails open', async () => {
    const env = makeEnv({ mode: 'vad', ctxState: 'suspended' });
    env.resumeBlocked = true;
    env.devs.default.level = QUIET;
    await joined(env, 1, []);
    env.advance(200);
    check('a suspended analysis context never silences the member', env.mic().enabled === true);
    const env2 = makeEnv({ mode: 'vad', noClone: true });
    env2.devs.default.level = QUIET;
    await joined(env2, 1, []);
    env2.advance(200);
    check('no clone support: the gate stays open', env2.mic().enabled === true);
    const env3 = makeEnv({ mode: 'vad', noAudio: true });
    await joined(env3, 1, []);
    check('no AudioContext at all: the gate stays open', env3.mic().enabled === true);
    const env4 = makeEnv({ mode: 'vad', ctxState: 'suspended' });
    env4.devs.default.level = LOUD;
    await joined(env4, 1, []);
    env4.advance(60);
    check('a context that resumes later starts gating', (env4.openCtxs().length > 0) && env4.mic().enabled === true);
    env4.devs.default.level = QUIET;
    env4.advance(1000);
    check('once running, silence closes it', env4.mic().enabled === false);
  });

  // ---- push-to-talk and its release delay ----------------------------------------------
  await scenario('ptt', async () => {
    const env = makeEnv({ mode: 'ptt' });
    await joined(env, 1, []);
    const mic = env.mic();
    check('PTT starts closed', mic.enabled === false);
    env.doc.fire('keydown', { code: 'Space' });
    check('the key opens it', mic.enabled === true && env.speaking().slice(-1)[0] === true);
    env.doc.fire('keyup', { code: 'Space' });
    check('delay 0: letting go closes it at once', mic.enabled === false && env.speaking().slice(-1)[0] === false);
    env.VC.setPttDelay(300);
    env.doc.fire('keydown', { code: 'Space' });
    env.doc.fire('keyup', { code: 'Space' });
    check('a 300 ms delay keeps the track open after release', mic.enabled === true && env.liveTimeouts() === 1);
    check('the timer is the configured one', env.timeouts.filter(t => t.live)[0].ms === 300);
    env.advance(290);
    check('still open just before 300 ms', mic.enabled === true);
    env.advance(20);
    check('closed after 300 ms, and speaking withdrawn', mic.enabled === false && env.speaking().slice(-1)[0] === false && env.liveTimeouts() === 0);
    env.doc.fire('keydown', { code: 'Space' });
    env.doc.fire('keyup', { code: 'Space' });
    env.advance(100);
    env.doc.fire('keydown', { code: 'Space' });
    check('pressing again inside the delay cancels the pending close', env.liveTimeouts() === 0 && mic.enabled === true);
    env.advance(1000);
    check('and the key still held keeps it open', mic.enabled === true);
    env.doc.fire('keyup', { code: 'Space' });
    env.VC.leave();
    check('leaving inside the delay clears the timer', env.liveTimeouts() === 0);
    const before = env.speaking().length;
    env.advance(1000);
    check('nothing is sent after the call has ended', env.speaking().length === before);
    // unmuting must not open a PTT microphone
    const env2 = makeEnv({ mode: 'ptt' });
    await joined(env2, 1, []);
    env2.VC.toggleMute(); env2.VC.toggleMute();
    check('unmuting in PTT mode does not leave the microphone open', env2.mic().enabled === false);
    env2.doc.fire('keydown', { code: 'Space' });
    check('PTT works after unmuting', env2.mic().enabled === true);
    env2.VC.toggleMute();
    check('muting while the key is held closes it', env2.mic().enabled === false);
    env2.doc.fire('keyup', { code: 'Space' });
    // a mode change inside the delay
    const env3 = makeEnv({ mode: 'ptt' });
    env3.VC.init(env3.ws, null, null, 1);
    env3.VC.setPttDelay(500);
    await env3.VC.join();
    env3.doc.fire('keydown', { code: 'Space' });
    env3.doc.fire('keyup', { code: 'Space' });
    env3.VC.setMode('vad');
    check('changing mode inside the delay clears it', env3.liveTimeouts() === 0);
    check('the delay is kept in localStorage only',
      JSON.parse(env3.storage.voice_prefs).pttDelay === 500 && !env3.sent.some(m => /500|pttDelay/.test(m)), env3.sent.join(' '));
    env3.VC.leave();
  });

  // ---- level meter ---------------------------------------------------------------------
  await scenario('meter in a call', async () => {
    const env = makeEnv({ mode: 'ptt' });
    await joined(env, 1, [2]);
    const calls = env.gumCalls.length;
    const seen = [];
    env.VC.startMeter(info => seen.push(info));
    await flush();
    check('in a call the meter opens no second microphone', env.gumCalls.length === calls && env.liveHandles().length === 1);
    env.devs.default.level = LOUD;
    env.advance(100);
    const last = seen[seen.length - 1];
    check('the meter moves while the member speaks (reads -20 dBFS)', last && Math.abs(last.db - db(LOUD)) < 0.01 && last.inCall === true, JSON.stringify(last));
    check('it reads the level while the PTT track is closed', env.mic().enabled === false);
    env.devs.default.level = QUIET;
    env.advance(100);
    check('and falls when the sound stops', seen[seen.length - 1].db < -60);
    env.VC.toggleMute();
    env.devs.default.level = LOUD;
    env.advance(100);
    check('it keeps reading while muted', Math.abs(seen[seen.length - 1].db - db(LOUD)) < 0.01);
    env.VC.stopMeter();
    check('closing the panel in a call leaves the live microphone alone', env.mic() && !env.mic().stopped && env.VC.isInVoice());
    check('and stops the meter timer and its clone', env.liveClones().length === 0 && env.liveIntervals() === 0);
    check('no peer was dropped', env.pcs.every(p => !p.closed));
    const n = seen.length;
    env.advance(500);
    check('no more levels after stopMeter', seen.length === n);
    env.VC.leave();
    check('everything is released at the end', env.liveHandles().length === 0 && env.liveClones().length === 0 && env.openCtxs().length === 0);

    // VAD mode: the meter and the gate side by side
    const env2 = makeEnv({ mode: 'vad' });
    env2.devs.default.level = QUIET;
    await joined(env2, 1, []);
    const seen2 = [];
    env2.VC.startMeter(i => seen2.push(i));
    env2.devs.default.level = LOUD;
    env2.advance(100);
    check('VAD gate and meter each read their own clone', env2.liveClones().length === 2 && env2.mic().enabled === true
      && Math.abs(seen2[seen2.length - 1].db - db(LOUD)) < 0.01);
    env2.VC.stopMeter();
    check('stopping the meter leaves the VAD analysis running', env2.liveClones().length === 1 && env2.liveIntervals() === 1);
    env2.VC.leave();
  });

  await scenario('meter outside a call', async () => {
    const env = makeEnv({ mode: 'vad' });
    env.VC.init(env.ws, null, null, 1);
    env.devs.default.level = LOUD;
    const seen = [];
    env.VC.startMeter(i => seen.push(i));
    await flush();
    env.VC.startMeter(i => seen.push(i));
    await flush();
    check('outside a call the meter opens the microphone once', env.gumCalls.length === 1 && env.liveHandles().length === 1, env.gumCalls.length);
    env.advance(100);
    check('it reports the level and that no call is running', seen.length > 0 && seen[seen.length - 1].inCall === false
      && Math.abs(seen[seen.length - 1].db - db(LOUD)) < 0.01);
    env.VC.stopMeter();
    check('closing the panel releases the microphone, the context and the timer',
      env.liveHandles().length === 0 && env.openCtxs().length === 0 && env.liveIntervals() === 0);
    check('the panel can be opened again', (env.VC.startMeter(() => {}), true));
    await flush();
    check('and opens the microphone again', env.gumCalls.length === 2 && env.liveHandles().length === 1);
    env.VC.stopMeter();

    // join with the panel open: one open handle, the panel then reads the live stream
    const e2 = makeEnv({ mode: 'ptt' });
    e2.VC.init(e2.ws, null, null, 1);
    const s2 = [];
    e2.VC.startMeter(i => s2.push(i));
    await flush();
    await e2.VC.join();
    e2.VC.handleMessage({ type: 'voice_state', channel: 'general', resume_token: 'tok', users: [{ user_id: 1, username: 'u1' }] });
    await flush();
    check('joining with the panel open does not open the device twice',
      e2.liveAtCall.length === 2 && e2.liveAtCall[1] === 0 && e2.liveHandles().length === 1, JSON.stringify(e2.liveAtCall));
    e2.devs.default.level = LOUD;
    e2.advance(100);
    check('the panel now reads the call and says so', s2[s2.length - 1].inCall === true && Math.abs(s2[s2.length - 1].db - db(LOUD)) < 0.01);
    e2.VC.leave();
    await flush();
    check('after leaving, the panel (still open) reads its own microphone again', e2.gumCalls.length === 3 && e2.liveHandles().length === 1);
    e2.VC.stopMeter();
    check('closing it then releases everything', e2.liveHandles().length === 0 && e2.liveClones().length === 0 && e2.openCtxs().length === 0);

    // refused permission
    const e3 = makeEnv({ mode: 'vad' });
    e3.gumError = 'NotAllowedError';
    const s3 = [];
    e3.VC.startMeter(i => s3.push(i));
    await flush();
    check('a refused microphone gives the panel an error, not an exception', s3.length === 1 && /refused/i.test(s3[0].error || ''), JSON.stringify(s3));
    e3.VC.stopMeter();
    check('and nothing stays open', e3.liveHandles().length === 0 && e3.openCtxs().length === 0);

    // closed while the browser is still asking
    const e4 = makeEnv({ mode: 'vad' });
    e4.holdGum = true;
    e4.VC.startMeter(() => {});
    e4.VC.stopMeter();
    e4.pendingGum.forEach(p => p.release());
    await flush();
    check('a microphone that arrives after the panel was closed is released at once',
      e4.opened.length === 1 && e4.opened[0].stopped === true && e4.openCtxs().length === 0 && e4.liveIntervals() === 0);
    // device chosen in the panel while it is open
    const e5 = makeEnv({ mode: 'vad' });
    e5.VC.init(e5.ws, null, null, 1);
    e5.VC.startMeter(() => {});
    await flush();
    await e5.VC.setInputDevice('usb-2');
    await flush();
    check('choosing a device in the open panel moves the meter to it and releases the old one',
      e5.gumCalls.length === 2 && e5.gumCalls[1].audio.deviceId.exact === 'usb-2' && e5.liveHandles().length === 1 && e5.liveHandles()[0].src.id === 'usb-2');
    e5.VC.stopMeter();
  });

  // ---- loopback -----------------------------------------------------------------------
  await scenario('loopback', async () => {
    const env = makeEnv({ mode: 'vad' });
    env.VC.init(env.ws, null, null, 1);
    check('loopback needs the meter', env.VC.setLoopback(true) === false);
    env.VC.startMeter(() => {});
    await flush();
    check('loopback is off until asked for', env.openCtxs().every(c => !c.nodes.some(n => n.kind === 'gain')));
    check('it can be turned on outside a call', env.VC.setLoopback(true) === true);
    const meterCtx = env.openCtxs()[0];
    const gain = meterCtx.nodes.find(n => n.kind === 'gain');
    const source = meterCtx.nodes.find(n => n.kind === 'source');
    check('it plays through the meter context to its own output only',
      gain && gain.outs[0] === meterCtx.destination && source.outs.includes(gain));
    check('it never touches a peer connection', env.pcs.length === 0);
    check('nothing about it is sent', env.sent.length === 0);
    env.VC.setLoopback(false);
    check('it can be turned off', gain.disconnected === true && !source.outs.includes(gain));
    env.VC.setLoopback(true);
    env.VC.stopMeter();
    check('closing the panel turns it off and releases the microphone', gain.disconnected === true && env.liveHandles().length === 0);
    // join while it is on
    const e2 = makeEnv({ mode: 'ptt' });
    e2.VC.init(e2.ws, null, null, 1);
    e2.VC.startMeter(() => {});
    await flush();
    e2.VC.setLoopback(true);
    const g2 = e2.openCtxs()[0].nodes.find(n => n.kind === 'gain');
    await e2.VC.join();
    await flush();
    check('joining a call turns the loopback off', g2.disconnected === true);
    check('it is refused during a call', e2.VC.setLoopback(true) === false);
    e2.VC.leave();
    e2.VC.stopMeter();
  });

  // ---- switching the microphone during a call -------------------------------------------
  await scenario('swap in a call', async () => {
    const env = makeEnv({ mode: 'ptt' });
    await joined(env, 1, [2, 3]);
    giveAudio(env, 0); giveAudio(env, 1);
    await env.VC.startScreenShare();
    await flush();
    const playCtx = env.ctxs[0];
    const gains = playCtx.nodes.filter(n => n.kind === 'gain');
    env.VC.setPeerVolume(2, 40);
    const old = env.mic();
    const pcsBefore = env.pcs.length;
    const sentBefore = env.sent.length;
    const ok = await env.VC.setInputDevice('usb-2');
    await flush();
    const fresh = env.mic();
    check('the switch reports success', ok === true);
    check('the new device is opened with its id', env.gumCalls[env.gumCalls.length - 1].audio.deviceId.exact === 'usb-2' && fresh.src.id === 'usb-2');
    check('every peer microphone sender got the new track',
      env.pcs.slice(0, 2).every(p => p.senders[0].replaced.length === 1 && p.senders[0].replaced[0] === fresh && p.senders[0].track === fresh));
    check('the screen share audio sender was not touched', env.pcs.slice(0, 2).every(p => p.senders.slice(1).every(s => s.replaced.length === 0)));
    check('no peer connection was closed or created', env.pcs.length === pcsBefore && env.pcs.every(p => !p.closed));
    check('the old track is stopped', old.stopped === true && env.sandbox.__VC.isInVoice());
    check('a PTT microphone stays closed after the switch', fresh.enabled === false);
    check('the new track is already closed when it goes into the senders (no burst of sound)',
      env.pcs.slice(0, 2).every(p => p.senders[0].enabledAtReplace.every(e => e === false)));
    check('the gain nodes of the other members stay attached and keep their volume',
      gains.every(g => !g.disconnected) && playCtx.closed === false && Math.abs(gains[0].gain.value - 0.4) < 1e-9);
    check('no leave or join went to the server', !env.sent.slice(sentBefore).some(m => /voice_leave|voice_join/.test(m)));
    // resume after a dropped socket still has its token
    env.ws.handlers.close.forEach(f => f({ code: 1006 }));
    const ws2 = { readyState: 1, sent: [], send(m) { this.sent.push(m); }, addEventListener() {} };
    env.VC.init(ws2, null, null, 1);
    env.advance(20);
    const resume = ws2.sent.map(m => JSON.parse(m)).find(m => m.type === 'voice_join');
    check('the resume token survives a switch', resume && resume.resume === true && resume.resume_token === 'tok' && resume.room === 'general', JSON.stringify(ws2.sent));
    // a peer that joins later gets the new track
    env.pcs.forEach(p => { p.connectionState = 'connected'; });   // audio kept flowing while the socket was down
    env.VC.handleMessage({ type: 'voice_state', channel: 'general', resumed: true, resume_token: 'tok',
      users: [1, 2, 3, 4].map(id => ({ user_id: id, username: 'u' + id })) });
    await flush();
    const newest = env.pcs[env.pcs.length - 1];
    check('a peer connected after the switch sends the new microphone', newest.senders[0].track === fresh);
    // the old microphone going away
    env.VC.toggleMute(); env.VC.toggleMute();
    const before = env.pcs.length;
    fresh.onended && fresh.onended();
    await flush();
    const after = env.mic();
    check('a microphone that disappears is replaced by the default one', after !== fresh && after.src.id === 'default'
      && !env.gumCalls[env.gumCalls.length - 1].audio.deviceId, JSON.stringify(env.gumCalls[env.gumCalls.length - 1]));
    check('the member is told and the peers keep their connections', env.toasts.some(t => /disconnected/.test(t)) && env.pcs.length === before && env.pcs.every(p => !p.closed));
    env.VC.leave();
  });

  await scenario('swap details', async () => {
    // VAD: the analysis follows the new microphone and the gate state carries over
    const env = makeEnv({ mode: 'vad' });
    env.devs.default.level = QUIET; env.devs['usb-2'].level = QUIET;
    await joined(env, 1, [2]);
    const seen = [];
    env.VC.startMeter(i => seen.push(i));
    const calls = env.gumCalls.length;
    await env.VC.setInputDevice('usb-2');
    await flush();
    check('a switch with the panel open opens one new device and no second one for the meter', env.gumCalls.length === calls + 1);
    check('the VAD analysis and the meter follow the new microphone', env.liveClones().length === 2
      && env.liveClones().every(c => c.src.id === 'usb-2'));
    env.devs['usb-2'].level = LOUD;
    env.advance(100);
    check('the new microphone opens the gate and moves the meter', env.mic().enabled === true && Math.abs(seen[seen.length - 1].db - db(LOUD)) < 0.01);
    check('only the one device is open', env.liveHandles().length === 1);
    env.VC.stopMeter();
    // muted: stays closed
    env.VC.toggleMute();
    await env.VC.setInputDevice('usb-1');
    await flush();
    check('a muted member stays closed after a switch', env.mic().enabled === false);
    env.VC.leave();
    check('nothing stays open after leaving', env.liveHandles().length === 0 && env.liveClones().length === 0);

    // two quick switches: the newest wins and the older stream is released
    const e2 = makeEnv({ mode: 'ptt' });
    await joined(e2, 1, [2]);
    e2.holdGum = true;
    const a = e2.VC.setInputDevice('usb-1');
    const b = e2.VC.setInputDevice('usb-2');
    e2.pendingGum.forEach(p => p.release());
    const ra = await a, rb = await b;
    await flush();
    check('of two overlapping switches only the newest takes effect', ra === false && rb === true && e2.mic().src.id === 'usb-2');
    check('the superseded microphone is released and the sender carries the newest',
      e2.liveHandles().length === 1 && e2.pcs[0].senders[0].track === e2.mic(), e2.liveHandles().length);
    // leaving while a switch is pending
    e2.pendingGum.length = 0;
    const c = e2.VC.setInputDevice('usb-1');
    e2.VC.leave();
    e2.pendingGum.forEach(p => p.release());
    const rc = await c;
    await flush();
    check('a switch that finishes after the call ended is released and changes nothing', rc === false && e2.liveHandles().length === 0);
    // a newer switch arrives while replaceTrack is still pending
    const e5 = makeEnv({ mode: 'ptt' });
    await joined(e5, 1, [2, 3]);
    e5.holdReplace = true;
    const first = e5.VC.setInputDevice('usb-1');
    await flush();
    const second = e5.VC.setInputDevice('usb-2');
    await flush();
    await releaseReplaces(e5);
    await first; await second;
    await flush();
    const live5 = e5.liveHandles();
    check('a switch overtaken during replaceTrack leaves exactly one microphone open (the newest)',
      live5.length === 1 && live5[0].src.id === 'usb-2' && e5.pcs.every(p => p.senders[0].track === live5[0]),
      live5.map(t => t.src.id).join());
    // a newer switch that then fails must not strand the peers the first one had not reached
    const e7 = makeEnv({ mode: 'ptt' });
    await joined(e7, 1, [2, 3]);
    e7.holdReplace = true;
    const f1 = e7.VC.setInputDevice('usb-1');
    await flush();
    e7.gumError = 'NotReadableError';
    const f2 = await e7.VC.setInputDevice('usb-2');
    e7.gumError = null;
    await releaseReplaces(e7);
    const r1 = await f1;
    await flush();
    check('a failed newer switch lets the first one finish for every peer',
      f2 === false && r1 === true && e7.liveHandles().length === 1 && e7.pcs.every(p => p.senders[0].track === e7.liveHandles()[0] && !p.senders[0].track.stopped));
    // the call ends while replaceTrack is still pending
    const e6 = makeEnv({ mode: 'ptt' });
    await joined(e6, 1, [2, 3]);
    e6.holdReplace = true;
    const pend = e6.VC.setInputDevice('usb-1');
    await flush();
    e6.VC.leave();
    await releaseReplaces(e6);
    await pend;
    await flush();
    check('a call that ends during replaceTrack leaves no microphone open', e6.liveHandles().length === 0 && e6.liveClones().length === 0,
      e6.liveHandles().map(t => t.src.id).join());
    // an unavailable device falls back
    const e3 = makeEnv({ mode: 'ptt' });
    await joined(e3, 1, [2]);
    e3.devs['usb-1'].gone = true;
    const r3 = await e3.VC.setInputDevice('usb-1');
    check('choosing a device that is gone during a call uses the default and tells the member',
      r3 === true && e3.mic().src.id === 'default' && e3.toasts.some(t => /not available/.test(t)));
    // refused: the call goes on with the old microphone
    const e4 = makeEnv({ mode: 'ptt' });
    await joined(e4, 1, [2]);
    const m4 = e4.mic();
    e4.gumError = 'NotReadableError';
    const r4 = await e4.VC.setInputDevice('usb-2');
    check('a failed switch keeps the call and the old microphone', r4 === false && e4.mic() === m4 && !m4.stopped && e4.VC.isInVoice());
  });

  // ---- output device -----------------------------------------------------------------------
  await scenario('output', async () => {
    const env = makeEnv({ mode: 'ptt', ctxSink: true, elSink: true });
    check('with AudioContext.setSinkId the picker is offered', env.VC.isOutputSupported() === true);
    await joined(env, 1, [2]);
    giveAudio(env, 0);
    env.VC.setOutputDevice('spk-1');
    check('the playback context is moved to the chosen speaker', env.ctxs[0].sink === 'spk-1', JSON.stringify(env.sinkCalls));
    check('the choice is stored in localStorage only', JSON.parse(env.storage.voice_prefs).outputDeviceId === 'spk-1'
      && !env.sent.some(m => /spk-1/.test(m)));
    env.VC.leave();
    await env.VC.join();
    check('a later call starts on the chosen speaker', env.ctxs.filter(c => c.sink === 'spk-1').length >= 2);
    env.VC.setOutputDevice('');
    check('choosing the default goes back to it', env.ctxs[env.ctxs.length - 1].sink === '' || env.ctxs.filter(c => !c.closed).some(c => c.sink === ''));
    env.VC.leave();

    const rej = makeEnv({ mode: 'ptt', ctxSink: true, sinkReject: true });
    await joined(rej, 1, [2]);
    rej.VC.setOutputDevice('gone');
    rej.VC.setOutputDevice('gone2');
    await flush();
    check('a speaker that cannot be used says so once and the call goes on', rej.toasts.filter(t => /speaker/.test(t)).length === 1 && rej.VC.isInVoice());
    rej.VC.leave();

    const ff = makeEnv({ mode: 'ptt', elSink: true });
    check('where only the element has setSinkId the picker stays hidden (the audio plays through Web Audio)', ff.VC.isOutputSupported() === false);
    ff.VC.setOutputDevice('x');
    check('and choosing one anyway changes nothing and does not throw', ff.sinkCalls.length === 0);
    const none = makeEnv({ mode: 'ptt' });
    check('with no setSinkId anywhere the picker stays hidden', none.VC.isOutputSupported() === false);
    const ios = makeEnv({ mode: 'ptt', elSink: true, ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)' });
    check('where audio plays through the element, element support counts', ios.VC.isOutputSupported() === true);
    await joined(ios, 1, [2]);
    giveAudio(ios, 0);
    ios.VC.setOutputDevice('spk-9');
    check('and the element is moved', ios.doc.getElementById('voice-audio-2').sinkCalls.slice(-1)[0] === 'spk-9');
    ios.VC.leave();
  });

  // ---- device lists and devicechange -----------------------------------------------------
  await scenario('devices', async () => {
    const env = makeEnv({ mode: 'vad', ctxSink: true });
    env.deviceList = [
      { kind: 'audioinput', deviceId: '', label: '' },
      { kind: 'audioinput', deviceId: 'default', label: 'Default - Built-in' },
      { kind: 'audioinput', deviceId: 'usb-1', label: 'USB Microphone' },
      { kind: 'audiooutput', deviceId: 'spk-1', label: 'Headphones' },
      { kind: 'videoinput', deviceId: 'cam', label: 'Camera' },
    ];
    env.VC.init(env.ws, null, null, 1);
    let l = await env.VC.listDevices();
    check('inputs and outputs are listed, other kinds and unnamed placeholders are not',
      l.inputs.length === 2 && l.outputs.length === 1 && l.inputs[1].label === 'USB Microphone' && l.outputSupported === true, JSON.stringify(l));
    check('nothing is flagged missing when no device was chosen', l.inputMissing === false && l.outputMissing === false);
    await env.VC.setInputDevice('usb-9');
    env.VC.setOutputDevice('spk-9');
    l = await env.VC.listDevices();
    check('a chosen device that is no longer listed is flagged', l.inputMissing === true && l.outputMissing === true);
    env.deviceList = [{ kind: 'audioinput', deviceId: '', label: '' }];
    l = await env.VC.listDevices();
    check('before permission (no usable ids) nothing is flagged', l.inputMissing === false);
    let n = 0;
    const off = env.VC.onDevicesChanged(() => { n++; });
    env.fireDeviceChange();
    check('a devicechange event reaches the panel', n === 1);
    off();
    env.fireDeviceChange();
    check('and stops after unsubscribing', n === 1);
    const again = env.VC.onDevicesChanged(() => { n++; });
    again();
    check('the browser event is attached once however often the panel opens', env.deviceWatchers.length === 1);
    const bare = makeEnv({ mode: 'vad', noEnumerate: true });
    const lb = await bare.VC.listDevices();
    check('a browser without enumerateDevices gives empty lists', lb.inputs.length === 0 && lb.outputs.length === 0);
  });

  // ---- what leaves the browser ----------------------------------------------------------------
  await scenario('wire', async () => {
    const env = makeEnv({ mode: 'ptt', ctxSink: true });
    env.VC.init(env.ws, null, null, 1);
    await env.VC.setInputDevice('usb-1');
    env.VC.setOutputDevice('spk-1');
    env.VC.setPttDelay(250);
    env.VC.setVadThreshold(-42);
    env.VC.startMeter(() => {});
    await flush();
    env.VC.setLoopback(true);
    env.VC.stopMeter();
    await env.VC.join();
    env.VC.handleMessage({ type: 'voice_state', channel: 'general', resume_token: 'tok', users: [{ user_id: 1, username: 'u1' }, { user_id: 2, username: 'u2' }] });
    await flush();
    env.doc.fire('keydown', { code: 'Space' });
    env.doc.fire('keyup', { code: 'Space' });
    env.advance(400);
    env.VC.toggleMute();
    env.VC.setMode('vad');
    env.VC.leave();
    const types = new Set(env.types());
    check('only the usual voice messages are sent', [...types].every(t => ['voice_join', 'voice_leave', 'voice_speaking', 'voice_mute', 'voice_deafen', 'voice_signal'].includes(t)), [...types].join());
    check('no message carries a device id, threshold, delay or loopback state',
      !env.sent.some(m => /usb-1|spk-1|deviceId|sinkId|threshold|pttDelay|delay|loopback|-42|250/i.test(m)), env.sent.join(' '));
    const keys = Object.keys(env.storage).sort();
    check('the only things stored are the preference entry and the one-time notice marker', keys.join() === 'voice_gate_notice_seen,voice_prefs', keys.join());
    check('the marker holds no setting', env.storage.voice_gate_notice_seen === '1', env.storage.voice_gate_notice_seen);
    const stored = JSON.parse(env.storage.voice_prefs);
    check('it holds the device ids, threshold and delay', stored.inputDeviceId === 'usb-1' && stored.outputDeviceId === 'spk-1' && stored.pttDelay === 250 && stored.vadThreshold === -42, JSON.stringify(stored));
  });

  // ---- the older behaviour that must not change -----------------------------------------------
  // ---- a socket reconnect during a call keeps the live settings --------------------
  await scenario('reconnect keeps prefs', async () => {
    const env = makeEnv({ mode: 'vad' });
    env.devs.default.level = QUIET;
    await joined(env, 1, [2]);
    const mic = env.mic();
    env.VC.setVadThreshold(-30);
    // another tab saves PTT, a threshold and a delay; this tab's socket reconnects
    env.storage.voice_prefs = JSON.stringify({ mode: 'ptt', vadThreshold: -80, pttDelay: 700, pttKey: 'KeyV' });
    env.ws.handlers.close.forEach(f => f({ code: 1006 }));
    const ws2 = { readyState: 1, sent: [], send(m) { this.sent.push(m); }, addEventListener() {} };
    env.VC.init(ws2, null, null, 1);
    env.advance(20);
    const p = env.VC.getPrefs();
    check('a reconnect during a call keeps the mode in use', p.mode === 'vad', JSON.stringify(p));
    check('and the threshold, delay and key in use', p.vadThreshold === -30 && p.pttDelay === 0 && p.pttKey === 'Space', JSON.stringify(p));
    check('the VAD analysis still runs and there is no PTT key listener', env.liveClones().length === 1 && env.doc.listeners('keydown') === 0);
    env.devs.default.level = LOUD;
    env.advance(60);
    check('the member is heard after the reconnect (the gate opens on speech)', mic.enabled === true);
    env.devs.default.level = QUIET;
    env.advance(900);
    check('and the gate closes again after the hang time', mic.enabled === false);
    env.VC.leave();
    // outside a call the stored settings are still picked up on init
    env.VC.init(ws2, null, null, 1);
    const q = env.VC.getPrefs();
    check('outside a call init still reloads the stored settings',
      q.mode === 'ptt' && q.vadThreshold === -80 && q.pttDelay === 700 && q.pttKey === 'KeyV', JSON.stringify(q));
  });

  // ---- push-to-talk keys and the element that has the focus ---------------------------------
  await scenario('ptt focus guard', async () => {
    const BUTTON = { tagName: 'BUTTON' };
    const INPUT = { tagName: 'INPUT' };
    const AREA = { tagName: 'TEXTAREA' };
    const EDIT = { tagName: 'DIV', isContentEditable: true };
    const MENU = { tagName: 'DIV', closest: (sel) => sel === '.voice-user-menu' ? {} : null };
    const MENUBTN = { tagName: 'BUTTON', closest: (sel) => sel === '.voice-user-menu' ? {} : null };
    const OTHER = { tagName: 'DIV', closest: () => null };
    // does the key open the microphone with this element focused?
    async function opens(key, target) {
      const env = makeEnv({ mode: 'ptt', storage: { voice_prefs: JSON.stringify({ mode: 'ptt', pttKey: key }) } });
      await joined(env, 1, []);
      env.doc.fire('keydown', { code: key, target });
      const on = env.mic().enabled === true && env.speaking().slice(-1)[0] === true;
      env.doc.fire('keyup', { code: key, target });
      const off = env.mic().enabled === false;
      env.VC.leave();
      return on && off ? 'open' : 'closed';
    }
    check('V as the key transmits with a button focused', await opens('KeyV', BUTTON) === 'open');
    check('Control as the key transmits with a button focused', await opens('ControlLeft', BUTTON) === 'open');
    check('V transmits with a button in the volume popover focused', await opens('KeyV', MENUBTN) === 'open');
    check('V transmits with the volume popover itself focused', await opens('KeyV', MENU) === 'open');
    check('Space as the key does not transmit with a button focused (the button is pressed)', await opens('Space', BUTTON) === 'closed');
    check('Enter as the key does not transmit with a button focused', await opens('Enter', BUTTON) === 'closed');
    check('the numpad Enter does not either', await opens('NumpadEnter', BUTTON) === 'closed');
    check('Space as the key does not transmit inside the volume popover', await opens('Space', MENU) === 'closed' && await opens('Space', MENUBTN) === 'closed');
    check('Space transmits with no button focused', await opens('Space', OTHER) === 'open' && await opens('Space', undefined) === 'open');
    check('typing in a field never transmits (V in an input, a textarea, an editable element)',
      await opens('KeyV', INPUT) === 'closed' && await opens('KeyV', AREA) === 'closed' && await opens('KeyV', EDIT) === 'closed');
    check('Space in an input does not transmit', await opens('Space', INPUT) === 'closed');
  });

  // ---- a save before init() must not wipe what is stored -------------------------------
  await scenario('prefs loaded at module load', async () => {
    const stored = { mode: 'vad', vadThreshold: -30, pttDelay: 300, inputDeviceId: 'usb-1', outputDeviceId: 'spk-1', pttKey: 'KeyV', noiseGate: true };
    const env = makeEnv({ storage: { voice_prefs: JSON.stringify(stored) } });
    const p0 = env.VC.getPrefs();
    check('the stored choices are read when the script loads, before init()',
      p0.vadThreshold === -30 && p0.pttDelay === 300 && p0.inputDeviceId === 'usb-1' && p0.outputDeviceId === 'spk-1' && p0.pttKey === 'KeyV', JSON.stringify(p0));
    // the settings window can save before the chat socket has opened
    env.VC.setPttDelay(500);
    let now = JSON.parse(env.storage.voice_prefs);
    check('a save before init() keeps the stored threshold, device ids and key',
      now.vadThreshold === -30 && now.inputDeviceId === 'usb-1' && now.outputDeviceId === 'spk-1' && now.pttKey === 'KeyV' && now.pttDelay === 500, JSON.stringify(now));
    env.VC.setMode('ptt');
    env.VC.setOutputDevice('spk-2');
    now = JSON.parse(env.storage.voice_prefs);
    check('so do the mode and output saves before init()', now.vadThreshold === -30 && now.inputDeviceId === 'usb-1' && now.mode === 'ptt' && now.outputDeviceId === 'spk-2', JSON.stringify(now));
    await env.VC.setInputDevice('usb-2');
    now = JSON.parse(env.storage.voice_prefs);
    check('and the input device save before init()', now.vadThreshold === -30 && now.pttDelay === 500 && now.inputDeviceId === 'usb-2', JSON.stringify(now));
  });

  // ---- a strict saved threshold now gates: one notice, value kept -----------------------------
  await scenario('gate notice', async () => {
    const MARK = 'voice_gate_notice_seen';
    const withThr = (thr, extra) => ({ voice_prefs: JSON.stringify(Object.assign({ mode: 'vad', vadThreshold: thr }, extra || {})) });
    const env = makeEnv({ storage: withThr(-30) });
    check('a stored threshold of -30 is kept', env.VC.getPrefs().vadThreshold === -30);
    check('the marker is not set until the notice has been shown', !(MARK in env.storage), Object.keys(env.storage).join());
    const text = env.VC.takeGateNotice();
    check('the notice tells the member the threshold now gates the microphone and how to lower it',
      /threshold/i.test(text) && /-30/.test(text) && /others|other people/i.test(text) && /left|lower/i.test(text), text);
    check('it is plain ASCII text, no markup and no emoji', /^[\x20-\x7e]+$/.test(text) && !/[<>&]/.test(text), text);
    check('the marker is set when it is shown', env.storage[MARK] === '1');
    check('a second look gives nothing', env.VC.takeGateNotice() === '');
    check('showing it did not change the threshold', JSON.parse(env.storage.voice_prefs).vadThreshold === -30 && env.VC.getPrefs().vadThreshold === -30);
    const again = makeEnv({ storage: env.storage });
    check('and at the next page load it is not shown again', again.VC.takeGateNotice() === '' && again.VC.getPrefs().vadThreshold === -30);
    // a page that never opened the settings window does not use the notice up
    const lazy = makeEnv({ storage: withThr(-25) });
    check('a page load without opening the window leaves it for later', !(MARK in lazy.storage));
    const lazy2 = makeEnv({ storage: lazy.storage });
    check('the next page load still has it', /-25/.test(lazy2.VC.takeGateNotice()));
    // the limit: -35 itself is not stricter
    const edge = makeEnv({ storage: withThr(-35) });
    check('-35 shows nothing', edge.VC.takeGateNotice() === '' && edge.storage[MARK] === '1' && edge.VC.getPrefs().vadThreshold === -35);
    const edge2 = makeEnv({ storage: withThr(-34) });
    check('-34 shows the notice', /-34/.test(edge2.VC.takeGateNotice()));
    const fresh = makeEnv({ storage: {} });
    check('a new member with the default threshold sees nothing', fresh.VC.takeGateNotice() === '' && fresh.storage[MARK] === '1');
    // a member who raises it later has chosen it
    fresh.VC.setVadThreshold(-20);
    const later = makeEnv({ storage: fresh.storage });
    check('a threshold raised after the first load shows nothing', later.VC.takeGateNotice() === '' && later.VC.getPrefs().vadThreshold === -20);
    const seen = makeEnv({ storage: Object.assign(withThr(-20), { [MARK]: '1' }) });
    check('an existing marker keeps the notice away', seen.VC.takeGateNotice() === '');
    const junk = makeEnv({ storage: withThr('abc') });
    check('a junk threshold gives the default and no notice', junk.VC.getPrefs().vadThreshold === -50 && junk.VC.takeGateNotice() === '');
    const nostore = makeEnv({ storageThrows: true });
    check('storage that throws gives no notice and no error', nostore.VC.takeGateNotice() === '');
    check('the notice is never sent to the server', (() => { env.VC.init(env.ws, null, null, 1); return !env.sent.some(m => /notice|threshold/i.test(m)); })());
  });

  // ---- join: one microphone request however often it is clicked ------------------------
  await scenario('join in flight', async () => {
    const env = makeEnv({ mode: 'vad' });
    env.VC.init(env.ws, null, null, 1);
    env.holdGum = true;
    const p1 = env.VC.join();
    const p2 = env.VC.join();
    await flush();
    check('a second click while the microphone is awaited does not ask again', env.gumCalls.length === 1, env.gumCalls.length);
    env.pendingGum.splice(0).forEach(g => g.release());
    await Promise.all([p1, p2]);
    await flush();
    check('one microphone is open in the call and none leaked', env.liveHandles().filter(t => !t.isClone).length === 1, env.liveHandles().length);
    check('one voice_join is sent', env.types().filter(t => t === 'voice_join').length === 1, env.types().join());
    check('the member is in the call', env.VC.isInVoice() === true);
    env.holdGum = false;
    await env.VC.join();
    check('a join while already in the call still does nothing', env.gumCalls.length === 1);
    env.VC.leave();
    check('leaving closes the one microphone', env.liveHandles().length === 0, env.liveHandles().length);
    // the guard is released again: a later join works
    await env.VC.join();
    check('after a leave a new join works', env.VC.isInVoice() === true && env.gumCalls.length === 2);
    env.VC.leave();

    // the guard is released after a refused microphone as well
    const e2 = makeEnv({ mode: 'vad' });
    e2.VC.init(e2.ws, null, null, 1);
    e2.gumError = 'NotAllowedError';
    await e2.VC.join();
    check('a refused microphone leaves the member out of the call', e2.VC.isInVoice() === false && e2.gumCalls.length === 1);
    e2.gumError = null;
    await e2.VC.join();
    check('and the next click asks again', e2.VC.isInVoice() === true && e2.gumCalls.length === 2, e2.gumCalls.length);
    e2.VC.leave();

    // the settings window changes device or opens while the join waits
    const e3 = makeEnv({ mode: 'vad' });
    e3.VC.init(e3.ws, null, null, 1);
    const seen3 = [];
    e3.VC.startMeter(i => seen3.push(i));
    await flush();
    check('the panel opened its own microphone', e3.gumCalls.length === 1 && e3.liveHandles().length === 1);
    e3.holdGum = true;
    const pj = e3.VC.join();
    await flush();
    check('the join let the panel microphone go and asked once', e3.gumCalls.length === 2 && e3.liveHandles().length === 0, e3.gumCalls.length);
    await e3.VC.setInputDevice('usb-1');
    e3.VC.startMeter(i => seen3.push(i));
    await flush();
    check('a device change or a panel opened during the wait opens no second microphone', e3.gumCalls.length === 2, JSON.stringify(e3.gumCalls));
    e3.holdGum = false;
    e3.pendingGum.splice(0).forEach(g => g.release());
    await pj;
    await flush();
    check('after the join the panel reads a clone of the call microphone, not a device of its own',
      e3.gumCalls.length === 2 && e3.liveHandles().filter(t => !t.isClone).length === 1 && e3.liveClones().length >= 1
      && e3.liveHandles().length === 1, e3.gumCalls.length + ' ' + e3.liveHandles().length + ' ' + e3.liveClones().length);
    check('and the meter reports levels', seen3.length > 0 && seen3[seen3.length - 1].error === null);
    e3.VC.leave();
    e3.VC.stopMeter();
    await flush();
    check('nothing stays open afterwards', e3.liveHandles().length === 0 && e3.liveClones().length === 0);

    // a refused microphone: the panel meter is rebuilt afterwards
    const e4 = makeEnv({ mode: 'vad' });
    e4.VC.init(e4.ws, null, null, 1);
    e4.VC.startMeter(() => {});
    await flush();
    e4.holdGum = true;
    const pf = e4.VC.join();
    await flush();
    e4.VC.startMeter(() => {});
    await flush();
    check('no meter microphone while the join waits (refused case)', e4.gumCalls.length === 2);
    e4.gumError = 'NotAllowedError';
    e4.holdGum = false;
    e4.pendingGum.splice(0).forEach(g => g.release());
    e4.gumError = null;
    await pf;
    await flush();
    check('after a refused join the panel opens its microphone again', e4.VC.isInVoice() === false && e4.gumCalls.length === 3 && e4.liveHandles().length === 1,
      e4.gumCalls.length + ' ' + e4.liveHandles().length);
    e4.VC.stopMeter();
  });

  // a microphone prompt that is never answered does not block Join for good (item 70)
  await scenario('unanswered prompt', async () => {
    let timer;
    const late = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('no answer within 10 s')), 10000); });
    try { await Promise.race([(async () => {
      const env = makeEnv({ mode: 'vad' });
      env.VC.init(env.ws, null, null, 1);
      env.holdGum = true;
      env.VC.join();
      await flush();
      env.VC.join();
      await flush();
      check('a second Join while the prompt waits opens nothing more', env.gumCalls.length === 1, env.gumCalls.length);
      env.advance(25000);
      await flush();
      env.VC.join();
      await flush();
      check('before 30 seconds the prompt is still waited for', env.gumCalls.length === 1, env.gumCalls.length);
      env.advance(6000);
      await flush();
      check('after 30 seconds the join gives up: not in the call and the join is released', env.VC.isInVoice() === false);
      check('a playback context made for the join is closed again', env.openCtxs().length === 0, env.openCtxs().length);
      env.VC.join();
      await flush();
      check('Join can be tried again after the timeout', env.gumCalls.length === 2, env.gumCalls.length);
      // the first prompt is answered at last: its stream is stopped, nothing joins
      env.pendingGum[0].release();
      await flush();
      check('a stream that arrives after the timeout is stopped at once (no hot microphone)', env.liveHandles().length === 0 && env.VC.isInVoice() === false,
        env.liveHandles().length + ' ' + env.VC.isInVoice());
      check('and nothing was sent to the server', env.types().indexOf('voice_join') < 0, env.types().join(','));
      // the second attempt completes normally
      env.holdGum = false;
      env.pendingGum[1].release();
      await flush();
      check('the second attempt joins when its prompt is answered', env.VC.isInVoice() === true && env.types().filter(t => t === 'voice_join').length === 1, env.types().join(','));
      env.VC.leave();
      check('and leaving releases the microphone', env.liveHandles().length === 0);
    })(), late]); } catch (e) { check('unanswered prompt (did not finish)', false, e && e.message); } finally { clearTimeout(timer); }
  });

  await scenario('unchanged', async () => {
    const env = makeEnv({ mode: 'vad' });
    env.devs.default.level = QUIET;
    await joined(env, 1, [2, 3]);
    giveAudio(env, 0);
    const g = env.ctxs[0].nodes.filter(n => n.kind === 'gain')[0];
    env.VC.toggleDeafen();
    check('deafen still silences through the gain nodes', g.gain.value === 0);
    env.VC.toggleDeafen();
    check('and restores them', g.gain.value === 1);
    env.VC.leave();
    check('leaving still closes the playback context', env.ctxs[0].closed === true);
    check('leave sends exactly one voice_leave', env.types().filter(t => t === 'voice_leave').length === 1);
  });

  results.forEach(r => console.log('RESULT ' + JSON.stringify(r)));
})();

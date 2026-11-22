// Runs static/js/vod-player.js under Node in a fresh sandbox per scenario: a small fake DOM, a fake Portal.fetch,
// a fake hls.js, a fake localStorage. usage: node vod_player_harness.js <vod-player.js>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }
const SRC = fs.readFileSync(process.argv[2], 'utf8');
const NAME = 'Show/2026-02-01/chunk_001.mkv';
const FOLDER = 'Show/2026-02-01';
const SESSION_URL = '/api/vods/session/Show/2026-02-01/index.m3u8';
const CHUNK_URL = '/api/vods/play/Show/2026-02-01/chunk_001.mkv.mp4';
const tick = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); };

class El {
  constructor(id) { this.id = id; this.style = {}; this.listeners = {}; this._text = ''; this.disabled = false; this.value = ''; this.href = ''; this.currentTime = 0; this.duration = 0; this.playbackRate = 1; this.src = ''; }
  addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); }
  fire(t) { (this.listeners[t] || []).forEach((fn) => fn({})); }
  set textContent(v) { this._text = String(v); }
  get textContent() { return this._text; }
  load() { this.loaded = (this.loaded || 0) + 1; }
  play() { return Promise.resolve(); }
  canPlayType() { return this.native ? 'maybe' : ''; }
}

function boot(opts) {
  const els = {};
  const store = Object.assign({}, opts.storage || {});
  const fetches = [];
  const toasts = [];
  const hlsInstances = [];
  const timers = [];
  class FakeHls {
    static isSupported() { return true; }
    constructor(cfg) { this.cfg = cfg; this.handlers = {}; this.destroyed = false; this.recovered = 0; this.restarts = 0; hlsInstances.push(this); }
    on(e, fn) { this.handlers[e] = fn; }
    loadSource(u) { this.source = u; }
    attachMedia(v) { this.media = v; }
    destroy() { this.destroyed = true; }
    startLoad() { this.restarts += 1; }
    recoverMediaError() { this.recovered += 1; }
  }
  FakeHls.Events = { ERROR: 'hlsError' };
  FakeHls.ErrorTypes = { NETWORK_ERROR: 'networkError', MEDIA_ERROR: 'mediaError' };
  const sandbox = {
    console, URL, URLSearchParams, JSON, Math, Date, Promise, parseFloat, parseInt, encodeURIComponent,
    document: {
      readyState: 'loading', pictureInPictureEnabled: false,
      getElementById: (id) => (els[id] = els[id] || new El(id)),
      addEventListener: (t, fn) => { if (t === 'DOMContentLoaded') sandbox.__init = fn; },
    },
    location: { search: '?name=' + encodeURIComponent(NAME) + (opts.query || ''), pathname: '/vods/play',
                href: 'https://portal.test/vods/play?name=' + encodeURIComponent(NAME) + (opts.query || '') },
    history: { replaceState: (a, b, url) => { sandbox.__lastUrl = url; } },
    localStorage: {
      get length() { return Object.keys(store).length; },
      key: (i) => Object.keys(store)[i],
      getItem: (k) => (k in store ? store[k] : null),
      setItem: (k, v) => { store[k] = String(v); },
      removeItem: (k) => { delete store[k]; },
    },
    Portal: {
      toast: (m) => toasts.push(m),
      fetch: async (url, o) => {
        fetches.push(url);
        const r = opts.respond(url, o, fetches.filter((u) => u === url).length);
        return { status: r.status, ok: r.status >= 200 && r.status < 300, body: null,
                 json: async () => r.data || {}, text: async () => r.text || '' };
      },
    },
    fetch: async () => ({ ok: false }),
    setTimeout: (fn, ms) => { timers.push(fn); return timers.length; },
    clearTimeout: () => {},
    window: null,
    Hls: opts.noHls ? undefined : FakeHls,
  };
  sandbox.window = sandbox;
  sandbox.addEventListener = () => {};
  vm.createContext(sandbox);
  const nodeVideo = (els['vp-video'] = new El('vp-video'));
  nodeVideo.native = !!opts.native;
  vm.runInContext(SRC, sandbox);
  sandbox.__init();
  return { sandbox, els, store, fetches, toasts, hlsInstances, timers, video: nodeVideo,
           async run(n) { for (let i = 0; i < (n || 6); i++) { await tick(); while (timers.length) timers.shift()(); } await tick(); } };
}

const PLAYLIST = '#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:300\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXTINF:300.000,\nchunk_000.ts\n#EXT-X-DISCONTINUITY\n#EXTINF:120.500,\nchunk_001.ts\n#EXT-X-ENDLIST\n';

function sessionResponder(first) {
  return (url) => {
    if (url === SESSION_URL) return first(url);
    return { status: 206 };
  };
}

(async () => {
  // 1. whole session through hls.js: a 202 first, then the playlist; the URL carries no credential
  let polls = 0;
  let t = boot({ query: '&mode=session', respond: sessionResponder(() => (++polls < 2 ? { status: 202, data: { state: 'preparing', done: 1, total: 2 } } : { status: 200, text: PLAYLIST })) });
  await t.run();
  check('session mode asks for the playlist first and shows the measuring state while it answers 202', polls >= 2 && t.fetches.includes(SESSION_URL) && !t.fetches.includes(CHUNK_URL));
  check('hls.js loads the session playlist with a plain relative URL (no token, no query)', t.hlsInstances.length === 1 && t.hlsInstances[0].source === SESSION_URL && !/[?#]/.test(t.hlsInstances[0].source));
  check('hls.js is attached to the video element', t.hlsInstances[0] && t.hlsInstances[0].media === t.video);
  const cfg = t.hlsInstances[0].cfg.fragLoadPolicy.default;
  check('a segment may take longer than the 55 s the portal waits, and a 503 is retried many times', cfg.maxTimeToFirstByteMs > 60000 && cfg.errorRetry.maxNumRetry >= 20 && cfg.errorRetry.retryDelayMs >= 1000);
  check('the whole-session summary is shown', /2 chunks/.test(t.els['vp-pos'].textContent) && /7 min/.test(t.els['vp-pos'].textContent), t.els['vp-pos'].textContent);
  check('nothing was asked of the single-chunk route', !t.fetches.includes(CHUNK_URL));
  check('the mode button says what it will do', t.els['vp-mode'].textContent === 'Play this chunk only' && t.els['vp-mode'].style.display === '');

  // 2. resume position is per session, not per chunk
  t.store['vodpos:session:' + FOLDER] = JSON.stringify({ t: 100, at: 1 });
  t.store['vodpos:' + NAME] = JSON.stringify({ t: 7, at: 1 });
  t.video.duration = 420; t.video.fire('loadedmetadata');
  check('the resume position of the session is applied', t.video.currentTime === 100, t.video.currentTime);
  t.video.currentTime = 250; t.video.fire('pause');
  const saved = JSON.parse(t.store['vodpos:session:' + FOLDER] || '{}');
  check('the position is saved under the session key and the chunk key is left alone', saved.t === 250 && JSON.parse(t.store['vodpos:' + NAME]).t === 7, JSON.stringify(t.store));
  t.video.fire('ended');
  check('ending clears the session position only', !('vodpos:session:' + FOLDER in t.store) && ('vodpos:' + NAME in t.store));

  // 3. a fatal 415 from a segment falls back to chunk by chunk
  polls = 0;
  t = boot({ query: '&mode=session', respond: sessionResponder(() => ({ status: 200, text: PLAYLIST })) });
  await t.run();
  const h = t.hlsInstances[0];
  h.handlers.hlsError('hlsError', { fatal: true, type: 'networkError', response: { code: 415 } });
  await t.run();
  check('a 415 segment falls back to the single-chunk player', h.destroyed && t.fetches.includes(CHUNK_URL) && t.toasts.some((m) => /chunk by chunk/.test(m)), JSON.stringify(t.fetches));
  check('the choice is remembered as chunk mode', t.store.vodmode === 'chunk' && /mode=chunk/.test(t.sandbox.__lastUrl || ''));

  // 4. other fatal errors: a network error restarts loading a few times, then falls back
  t = boot({ query: '&mode=session', respond: sessionResponder(() => ({ status: 200, text: PLAYLIST })) });
  await t.run();
  const h2 = t.hlsInstances[0];
  for (let i = 0; i < 3; i++) h2.handlers.hlsError('hlsError', { fatal: true, type: 'networkError', response: { code: 503 } });
  check('a fatal network error restarts loading up to three times', h2.restarts === 3 && !h2.destroyed);
  h2.handlers.hlsError('hlsError', { fatal: true, type: 'networkError', response: { code: 503 } });
  await t.run();
  check('then it falls back to chunk by chunk', h2.destroyed && t.fetches.includes(CHUNK_URL));
  h2.handlers.hlsError('hlsError', { fatal: false, type: 'networkError' });
  check('a non-fatal error is left to hls.js', h2.restarts === 3);

  // 5. a playlist that answers 415 or 409 falls back at once, 404 says not found
  for (const [status, label] of [[415, 'not playable'], [409, 'live'], [413, 'too long']]) {
    t = boot({ query: '&mode=session', respond: sessionResponder(() => ({ status, data: { error: 'x' } })) });
    await t.run();
    check('a playlist answering ' + status + ' (' + label + ') falls back to chunk by chunk', t.fetches.includes(CHUNK_URL) && t.hlsInstances.length === 0);
  }
  t = boot({ query: '&mode=session', respond: sessionResponder(() => ({ status: 404, data: {} })) });
  await t.run();
  check('a 404 playlist says the VOD was not found and plays nothing', /not found/.test(t.els['vp-message'].textContent) && !t.fetches.includes(CHUNK_URL));

  // 6. no hls.js and no native HLS: chunk by chunk; native HLS (Safari) uses the video element directly
  t = boot({ query: '&mode=session', noHls: true, respond: sessionResponder(() => ({ status: 200, text: PLAYLIST })) });
  await t.run();
  check('without hls.js or native HLS it falls back to chunk by chunk', t.fetches.includes(CHUNK_URL) && t.toasts.some((m) => /cannot play a whole session/.test(m)));
  t = boot({ query: '&mode=session', noHls: true, native: true, respond: sessionResponder(() => ({ status: 200, text: PLAYLIST })) });
  await t.run();
  check('natively (Safari) the video element gets the session URL', t.video.src === SESSION_URL && t.hlsInstances.length === 0);
  t.video.fire('error');
  await t.run();
  check('a native playback error falls back to chunk by chunk', t.fetches.includes(CHUNK_URL));

  // 7. the default stays the single chunk; the button switches, and the mode is remembered
  t = boot({ respond: (url) => (url === SESSION_URL ? { status: 200, text: PLAYLIST } : { status: 206 }) });
  await t.run();
  check('without a mode the single chunk is played as before', t.fetches.includes(CHUNK_URL) && !t.fetches.includes(SESSION_URL) && t.els['vp-mode'].textContent === 'Play whole session');
  t.els['vp-mode'].fire('click');
  await t.run();
  check('the button switches to the whole session and hides previous and next', t.fetches.includes(SESSION_URL) && t.hlsInstances.length === 1 && t.els['vp-prev'].style.display === 'none' && t.store.vodmode === 'session');
  t.els['vp-mode'].fire('click');
  await t.run();
  check('and back to the chunk, destroying the hls.js player', t.hlsInstances[0].destroyed && t.els['vp-prev'].style.display === '' && t.store.vodmode === 'chunk');
  t = boot({ storage: { vodmode: 'session' }, respond: (url) => (url === SESSION_URL ? { status: 200, text: PLAYLIST } : { status: 206 }) });
  await t.run();
  check('a remembered session mode is used when the URL says nothing', t.hlsInstances.length === 1);
  t = boot({ storage: { vodmode: 'session' }, query: '&mode=chunk', respond: (url) => ({ status: 206 }) });
  await t.run();
  check('the URL wins over the remembered mode', t.hlsInstances.length === 0 && t.fetches.includes(CHUNK_URL) && !t.fetches.includes(SESSION_URL));

  check('the player script has no inline handler and loads nothing from another host', !/onclick=/.test(SRC) && !/https?:\/\//.test(SRC.replace(/\/\*[\s\S]*?\*\//g, '')));
  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
})().catch((e) => { console.log('RESULT ' + JSON.stringify({ name: 'harness crashed', ok: false, detail: e && e.stack })); });

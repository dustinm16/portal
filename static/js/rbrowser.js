import RFB from '/static/vendor/novnc/core/rfb.js?v=1.4.0';
import keysyms from '/static/vendor/novnc/core/input/keysymdef.js';

/* Web Browser on the server: the page at /rbrowser (static/rbrowser.html).

   The page owns the WebSocket (as static/vnc.html does) so that it can read the close code, and hands it to
   noVNC. All the logic is in create(env): every outside thing (document, fetch, WebSocket, RFB, storage,
   timers, clock) is passed in, so tests/rbrowser_page_harness.js drives it under Node with fakes. The bottom
   of the file wires the real objects in when the page's markup is present.

   Text from the API goes into the page with textContent only; no HTML string is ever built from it. The VNC
   clipboard is off in both directions (no noVNC clipboard call or event is used here): text goes to the browser as
   typed key events, and text comes from it only through POST /api/rbrowser/session/clipboard. Nothing the member
   types, pastes or copies is logged or stored anywhere (the last text received is held in memory for the Copy
   button and dropped when the session ends). */

// ---- Constants a later measurement may change (design section 10, 7.3; gate round 1) -------------------
const MIN_W = 560;                 // narrowest remote window (Chromium's own minimum is 500); lead's decision D5
const MIN_H = 480;
const MAX_W = 1920;
const MAX_H = 1200;
const SNAP = 16;                   // sizes are multiples of this
const QUALITY_LEVELS = [           // noVNC qualityLevel / compressionLevel pairs; start values, gate G22
    { id: 'low', label: 'Low', quality: 2, compression: 7 },
    { id: 'balanced', label: 'Balanced', quality: 6, compression: 2 },
    { id: 'sharp', label: 'Sharp', quality: 9, compression: 0 },
];
const DEFAULT_QUALITY = 'balanced';
const TYPE_CHUNK = 40;             // characters per chunk of typeText; start value, gate G17
const TYPE_INTERVAL_MS = 30;       // pause between chunks; start value, gate G17
const TYPE_MAX_CHARS = 5000;       // typeText refuses more than this in one call
const ROUTE_BUSY_RETRY_MS = 1000;  // the type route answered 429 busy: asked again after this long
const ROUTE_RATE_RETRY_MS = 2000;  // ... or 429 rate limit
const ROUTE_RETRY_MAX_MS = 20000;  // and given up after this much waiting in all
// ---- Constants of the page itself ------------------------------------------------------------------------
const RECONNECT_DELAYS_MS = [1000, 2000, 5000];
const RECONNECT_CODES = [1006, 1001];
const RESIZE_DEBOUNCE_MS = 500;
const CONFIRM_DELAY_MS = 600;      // the confirm button ignores a click this soon after the question opens
const POLL_MS = 15000;
const POLL_WARN_MS = 3000;
const FRESH_MS = 5000;
const IDLE_WARN_S = 60;
const LIFETIME_WARN_S = 300;
const STATUS_RETRY_MS = 10000;
const NOTE_SHOW_MS = 8000;        // how long a note about typing stays on the picture when the text panel is shut
const CLIPBOARD_MAX = 262144;     // bytes of text the server returns from the browser; longer is cut and flagged
const QUALITY_KEY = 'rbrowser.quality';
const BOOT_KEY = 'rbrowser.boot';
const WS_PREFIX = '/ws/rbrowser/';

const KEY_RETURN = 0xff0d;
const KEY_TAB = 0xff09;
const KEY_BACKSPACE = 0xff08;
const SPECIAL_KEYS = {
    Backspace: KEY_BACKSPACE, Enter: KEY_RETURN, Tab: KEY_TAB, Escape: 0xff1b, Delete: 0xffff,
    ArrowLeft: 0xff51, ArrowUp: 0xff52, ArrowRight: 0xff53, ArrowDown: 0xff54,
    Home: 0xff50, End: 0xff57, PageUp: 0xff55, PageDown: 0xff56,
};
// Control, Shift, Super and Meta (left and right): released before pasted text is typed, because the
// member's Ctrl or Cmd key already reached the remote side as a key-down.
// Control, Shift, Alt, Super, Meta, Hyper (both sides) and AltGr (ISO_Level3_Shift, Mode_switch): released before a pasted text is typed
const MODIFIER_KEYSYMS = [0xffe3, 0xffe4, 0xffe1, 0xffe2, 0xffe9, 0xffea, 0xffeb, 0xffec, 0xffe7, 0xffe8, 0xffed, 0xffee, 0xfe03, 0xff7e];

const END_REASONS = {
    closed: 'You ended this session.',
    closed_in_browser: 'The last browser tab was closed, so the session ended.',
    idle: 'The session ended because it was idle for too long.',
    detached: 'The session ended because this page was away for too long.',
    max_lifetime: 'The session reached its time limit.',
    traffic_limit: 'The session used up its data allowance.',
    replaced: 'The session was replaced by one started from another sign-in.',
    signed_out: 'The session ended because you signed out.',
    admin_end: 'An administrator ended this session.',
    crash: 'The browser stopped unexpectedly.',
    portal_stop: 'The portal was restarted or stopped, which ends browser sessions. Start a new session.',
    start_failed: 'The browser could not be started.',
    settings_changed: 'An administrator switched the Web Browser off or changed who may use it, so the session ended.',
    slow: 'The connection was too slow to keep up. The session may still be running.',
    protocol: 'The connection sent data the portal does not accept, so it was closed.',
};
const END_FALLBACK = 'The session ended.';

// ---- Pure helpers ----------------------------------------------------------------------------------------
function snapDown(v) {
    return Math.floor(v / SNAP) * SNAP;
}

function clampSize(w, h) {
    w = Number(w); h = Number(h);
    if (!isFinite(w)) w = MIN_W;
    if (!isFinite(h)) h = MIN_H;
    w = Math.min(MAX_W, Math.max(MIN_W, snapDown(w)));
    h = Math.min(MAX_H, Math.max(MIN_H, snapDown(h)));
    return { width: w, height: h };
}

// The keysym that types one code point: the one noVNC's own keyboard sends for the same character (its keysymdef lookup: Latin-1 as
// itself, the legacy keysym where X11 has one such as Cyrillic, Polish letters, the euro sign and typographic punctuation, and
// 0x01000000 + code point for the rest). The module is the one the noVNC keyboard code imports (same URL, so the same instance), so
// the typed-text paths and a member typing on the picture give x11vnc one keysym per character, which the server's prepared keyboard map
// (rbrowser_unit/session.py KEYMAP_KEYSYMS) holds. Control characters give 0 (nothing to type); newline and tab are handled by the caller.
function keysymFor(cp) {
    if (cp >= 0x20 && cp <= 0x7e) return cp;
    if (cp >= 0xa0 && cp <= 0xff) return cp;
    if (cp > 0xff && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff)) return keysyms.lookup(cp);
    return 0;
}

function keysymsForText(text) {
    const keys = [];
    let skipped = 0;
    const chars = Array.from(String(text == null ? '' : text));
    for (let i = 0; i < chars.length; i++) {
        const ch = chars[i];
        const cp = ch.codePointAt(0);
        if (ch === '\r') {
            if (chars[i + 1] === '\n') i++;
            keys.push(KEY_RETURN);
        } else if (ch === '\n') {
            keys.push(KEY_RETURN);
        } else if (ch === '\t') {
            keys.push(KEY_TAB);
        } else {
            const k = keysymFor(cp);
            if (k) keys.push(k); else skipped++;
        }
    }
    return { keys: keys, skipped: skipped };
}

// The clipboard setting as the page uses it. The server's value for "send text only" is to_browser; "in" is accepted
// as the same thing. Anything else (an unknown or future value) counts as off, so a page never offers more than
// the server was meant to allow.
function normaliseClip(v) {
    if (v === 'both') return 'both';
    if (v === 'in' || v === 'to_browser') return 'in';
    return 'off';
}

// A deadline from the API as milliseconds since the epoch, or null. A number is epoch seconds (or
// milliseconds when it is very large); a number below 1e9 is read as seconds from the answer's arrival.
function parseDeadline(v, receivedAt) {
    if (typeof v === 'number' && isFinite(v)) {
        if (v >= 1e11) return v;
        if (v >= 1e9) return v * 1000;
        return receivedAt + v * 1000;
    }
    if (typeof v === 'string' && v) {
        const t = Date.parse(v);
        return isFinite(t) ? t : null;
    }
    return null;
}

function reasonText(reason) {
    if (typeof reason === 'string' && Object.prototype.hasOwnProperty.call(END_REASONS, reason)) return END_REASONS[reason];
    return END_FALLBACK;
}

// A CSS colour as "#rrggbb" (lower case), or '' when it is not one of rgb()/rgba() with plain numbers or a hex colour.
// The alpha value is ignored, except that a fully transparent colour means "no colour was set" and gives ''.
function colourToHex(text) {
    if (typeof text !== 'string') return '';
    const t = text.trim().toLowerCase();
    let m = /^#([0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$/.exec(t);
    if (m) {
        let h = m[1];
        if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
        if (h.length === 8) { if (h.slice(6) === '00') return ''; h = h.slice(0, 6); }
        return '#' + h;
    }
    m = /^rgba?\(\s*(\d{1,3})\s*[, ]\s*(\d{1,3})\s*[, ]\s*(\d{1,3})\s*(?:[,/]\s*(\d*\.?\d+%?)\s*)?\)$/.exec(t);
    if (!m) return '';
    if (m[4] !== undefined && parseFloat(m[4]) === 0) return '';
    let out = '#';
    for (let i = 1; i <= 3; i++) {
        const n = Number(m[i]);
        if (n > 255) return '';
        out += (n < 16 ? '0' : '') + n.toString(16);
    }
    return out;
}

// The member's portal theme as the server wants it at session start: the colour of the page's own toolbar (the same variable
// .rb-toolbar uses, --bg-secondary) and the mode (light only where theme.js set html[data-theme-mode="light"]). Null when the
// colour cannot be read; the server then keeps the neutral look. Nothing else about the theme is ever sent.
function readTheme(doc, win) {
    try {
        const bar = doc.getElementById('rb-toolbar');
        if (!bar || !win || typeof win.getComputedStyle !== 'function') return null;
        const color = colourToHex(win.getComputedStyle(bar).backgroundColor);
        if (!color) return null;
        const root = doc.documentElement;
        const light = !!root && typeof root.getAttribute === 'function' && root.getAttribute('data-theme-mode') === 'light';
        return { color: color, mode: light ? 'light' : 'dark' };
    } catch (e) {
        return null;
    }
}

// ---- The page ---------------------------------------------------------------------------------------------
function create(env) {
    const doc = env.doc;
    const win = env.win;
    const $ = (id) => doc.getElementById(id);
    const setTimer = (f, ms) => env.setTimeout(f, ms);
    const clearTimer = (t) => { if (t !== null && t !== undefined) env.clearTimeout(t); };

    let state = 'init';
    let session = null;
    let ws = null;
    let rfb = null;
    let conn = null;                 // { closed } of the current socket
    let generation = 0;
    let reconnectTry = 0;
    let reconnectTimer = null;
    let statusTimer = null;
    let resizeTimer = null;
    let noteTimer = null;
    let pollTimer = null;
    let tickTimer = null;
    let lastSize = null;
    let fit = true;
    let quality = DEFAULT_QUALITY;
    let currentBoot = '';
    let clipMode = 'off';            // off | in | both; anything the server sends that is not known counts as off
    let idleDeadline = null;
    let maxDeadline = null;
    let netWarning = false;
    let lastPollAt = 0;
    let polling = false;
    let suppressIdleUntil = 0;
    let ending = false;
    let asking = null;               // { at } while the End question is open
    let endBusy = false;
    let kbOpen = false;
    let composing = false;
    let useBeforeInput = false;
    let received = '';
    let clipBusy = false;
    let overlayActions = {};

    // typing queue
    let typeQueue = [];
    let typeTimer = null;
    let typing = false;
    let serverTyping = false;        // POST /api/rbrowser/session/type is used for text when the session offers it (info.type_text) until the server says it cannot (fallback: key events)
    let routeQueue = [];             // jobs typed through the server, one request at a time: { text | keys, resolve, release }
    let routing = false;

    // ---- storage (always inside try/catch) ----
    function storeGet(key) {
        try { return env.storage ? env.storage.getItem(key) : null; } catch (e) { return null; }
    }
    function storeSet(key, value) {
        try { if (env.storage) env.storage.setItem(key, value); } catch (e) { /* storage may be refused */ }
    }
    function storeDel(key) {
        try { if (env.storage) env.storage.removeItem(key); } catch (e) { /* storage may be refused */ }
    }

    // ---- small view helpers ----
    function setText(id, text) {
        const el = $(id);
        if (el) el.textContent = text;
    }
    function show(id, on) {
        const el = $(id);
        if (el) el.hidden = !on;
    }
    function badge(kind, text) {
        const el = $('rb-status');
        if (el) el.className = 'connection-status ' + kind;
        setText('rb-status-text', text);
    }

    // What each state shows. `spinner` marks a state that is waiting for something.
    const VIEWS = {
        loading: { kind: 'connecting', status: 'Loading...', title: 'Loading', text: 'Looking for your browser session.', spinner: true },
        checking: { kind: 'connecting', status: 'Checking the browser sandbox...', title: 'Checking the browser sandbox', text: 'The server is checking that the browser can run safely. This takes a few seconds.', spinner: true },
        starting: { kind: 'connecting', status: 'Starting...', title: 'Starting your browser', text: 'The browser is being started on the server. This takes a few seconds.', spinner: true },
        connecting: { kind: 'connecting', status: 'Connecting...', title: 'Connecting', text: 'Opening the picture of your browser.', spinner: true },
        connected: { kind: 'connected', status: 'Connected' },
        reconnecting: { kind: 'connecting', status: 'Reconnecting...', title: 'Reconnecting', text: 'The connection was lost. Trying again.', spinner: true },
        lost: { kind: 'disconnected', status: 'Disconnected', title: 'Connection lost', text: 'The connection to the browser was lost. The session may still be running.', action: ['Reconnect', 'resume'] },
        closed: { kind: 'disconnected', status: 'Disconnected', title: 'Disconnected', text: 'The connection closed.', action: ['Reconnect', 'resume'] },
        busy: { kind: 'disconnected', status: 'All sessions in use', title: 'All browser sessions are in use', text: '', action: ['Try again', 'start'] },
        elsewhere: { kind: 'disconnected', status: 'Running on another sign-in', title: 'Running on another sign-in', text: 'Your browser session was started from another sign-in of your account, for example on another device. You can end it and start a new one here; whatever is open in it is lost.', action: ['End it and start here', 'takeover'] },
        not_allowed: { kind: 'disconnected', status: 'Not allowed', title: 'Not allowed', text: 'Your account is not allowed to use the Web Browser on this server.', action: ['Back to the dashboard', 'dashboard'] },
        not_available: { kind: 'disconnected', status: 'Not available', title: 'Not available on this server', text: 'The Web Browser is not available on this server right now.', action: ['Back to the dashboard', 'dashboard'] },
        ended: { kind: 'disconnected', status: 'Session ended', title: 'Session ended', text: END_FALLBACK, action: ['Start again', 'start'] },
        restarted: { kind: 'disconnected', status: 'Portal restarted', title: 'The portal was restarted', text: 'The portal was restarted. Start a new session.', action: ['Start a new session', 'start'] },
        other_window: { kind: 'disconnected', status: 'Open in another window', title: 'Opened in another window', text: 'This session is open in another window of the same sign-in. Only one window can show it at a time.', action: ['Use this window', 'start'] },
        maintenance: { kind: 'disconnected', status: 'Maintenance', title: 'The portal is in maintenance', text: 'Try again in a little while.', action: ['Try again', 'start'] },
        error: { kind: 'disconnected', status: 'Error', title: 'Something went wrong', text: 'The page could not talk to the server.', action: ['Try again', 'start'] },
        login: { kind: 'disconnected', status: 'Signed out', title: 'Signed out', text: 'Going to the sign-in page.' },
    };

    function setState(name, opts) {
        opts = opts || {};
        state = name;
        const v = VIEWS[name];
        badge(v.kind, opts.status || v.status);
        const overlayOn = !!v.title;
        show('rb-overlay', overlayOn);
        if (overlayOn) {
            setText('rb-overlay-title', opts.title || v.title);
            setText('rb-overlay-text', opts.text !== undefined ? opts.text : v.text);
            show('rb-spinner', !!v.spinner);
            const note = opts.note || '';
            setText('rb-overlay-note', note);
            show('rb-overlay-note', !!note);
            overlayActions = {};
            const primary = opts.action || v.action || null;
            if (primary) {
                setText('rb-action', primary[0]);
                overlayActions.rb_action = primary[1];
            }
            show('rb-action', !!primary);
            const second = opts.action2 || null;
            if (second) {
                setText('rb-action2', second[0]);
                overlayActions.rb_action2 = second[1];
            }
            show('rb-action2', !!second);
        }
        const live = name === 'connected';
        const attached = live || name === 'reconnecting' || name === 'connecting';
        show('rb-keyboard', live);
        show('rb-text-toggle', live && clipMode !== 'off');
        show('rb-quality-wrap', live);
        show('rb-fit', live);
        show('rb-fullscreen', live && fullscreenSupported());
        show('rb-end', attached && !asking && !ending);
        if (!live) {
            show('rb-textpanel', false);
            setText('rb-text-toggle', 'Text');
            clearReceived();
            hideBanners();
        }
        if (name !== 'connected' && name !== 'connecting' && name !== 'reconnecting') {
            show('rb-confirm', false);
            asking = null;
        }
    }

    function hideBanners() {
        show('rb-banner-idle', false);
        show('rb-banner-life', false);
        show('rb-banner-traffic', false);
        hideNote();
    }

    function hideNote() {
        clearTimer(noteTimer); noteTimer = null;
        show('rb-banner-msg', false);
    }

    function runAction(which) {
        const name = overlayActions[which];
        if (name === 'start') return start();
        if (name === 'resume') { reconnectTry = 0; return resume(); }
        if (name === 'takeover') return create(true);
        if (name === 'dashboard') { env.location.assign('/'); return undefined; }
        return undefined;
    }

    function goLogin() {
        setState('login');
        env.location.assign('/login');
    }

    // ---- HTTP ----
    async function api(method, path, body) {
        try {
            const init = { method: method, credentials: 'same-origin', headers: { 'Accept': 'application/json' } };
            if (body !== undefined) {
                init.headers['Content-Type'] = 'application/json';
                init.body = JSON.stringify(body);
            }
            const r = await env.fetch(path, init);
            let data = {};
            if (r.status !== 204) {
                try { data = (await r.json()) || {}; } catch (e) { data = {}; }
            }
            return { status: r.status, ok: r.status >= 200 && r.status < 300, data: data };
        } catch (e) {
            return { status: 0, ok: false, data: {} };
        }
    }

    // ---- boot id: the page remembers the portal start it held a session under ----
    function rememberBoot() {
        if (currentBoot) storeSet(BOOT_KEY, currentBoot);
    }
    function forgetBoot() {
        storeDel(BOOT_KEY);
    }

    // ---- start-up flow ----
    function cancelTimers() {
        clearTimer(reconnectTimer); reconnectTimer = null;
        clearTimer(statusTimer); statusTimer = null;
        clearTimer(resizeTimer); resizeTimer = null;
        stopPolling();
    }

    function dropConnection() {
        generation++;
        clearTimer(resizeTimer); resizeTimer = null;
        const r = rfb;
        const s = ws;
        rfb = null; ws = null; conn = null;
        cancelTyping();
        if (r) { try { r.disconnect(); } catch (e) { /* already closed */ } }
        else if (s) { try { s.close(); } catch (e) { /* already closed */ } }
    }

    async function start() {
        cancelTimers();
        dropConnection();
        ending = false; asking = null; endBusy = false;
        reconnectTry = 0;
        const myGen = generation;
        setState('loading');
        const st = await api('GET', '/api/rbrowser/status');
        if (myGen !== generation) return;
        if (st.status === 401) { goLogin(); return; }
        if (!st.ok) { setState('error'); return; }
        const info = st.data;
        currentBoot = typeof info.boot_id === 'string' ? info.boot_id : '';
        if (info.available === false || info.enabled === false) {
            const reason = typeof info.reason === 'string' ? info.reason : '';
            setState('not_available', { note: reason });
            return;
        }
        if (info.allowed === false) { setState('not_allowed'); return; }
        if (typeof info.clipboard === 'string') clipMode = normaliseClip(info.clipboard);
        if (info.checking) {
            setState('checking');
            statusTimer = setTimer(() => { statusTimer = null; start(); }, STATUS_RETRY_MS);
            return;
        }
        const cur = await api('GET', '/api/rbrowser/session');
        if (myGen !== generation) return;
        if (cur.status === 401) { goLogin(); return; }
        if (cur.status === 403) { setState('not_allowed'); return; }
        if (cur.ok) { attach(cur.data); return; }
        if (cur.status === 409) { setState('elsewhere'); return; }
        if (cur.status === 404) {
            const seen = storeGet(BOOT_KEY);
            if (seen && currentBoot && seen !== currentBoot) {
                forgetBoot();
                setState('restarted');
                return;
            }
            await create(false);
            return;
        }
        setState('error');
    }

    async function create(takeover) {
        cancelTimers();
        dropConnection();
        const myGen = generation;
        setState('starting');
        const size = measure();
        const body = { width: size.width, height: size.height };
        if (takeover) body.takeover = true;
        const theme = readTheme(doc, win);       // read now, at session start: a later theme change applies to the next session
        if (theme) body.theme = theme;
        const r = await api('POST', '/api/rbrowser/session', body);
        if (myGen !== generation) return;
        if (r.ok) { attach(r.data); return; }
        const d = r.data || {};
        if (r.status === 401) { goLogin(); return; }
        if (r.status === 403) { setState('not_allowed'); return; }
        if (r.status === 409) {
            if (d.elsewhere) { setState('elsewhere'); return; }
            if (d.busy) {
                const n = Number(d.free_in_minutes);
                const text = n > 0 ? 'All browser sessions are in use. A seat should be free in about ' + Math.ceil(n) + ' minutes.'
                    : 'All browser sessions are in use. Try again in a little while.';
                setState('busy', { text: text });
                return;
            }
            setState('error', { text: 'The session could not be started.' });
            return;
        }
        if (r.status === 429) {
            setState('error', { title: 'Too many starts', text: 'You started too many sessions in a short time. Wait a few minutes and try again.' });
            return;
        }
        if (r.status === 503 && Number(d.retry_after) > 0) {
            setState('checking');
            statusTimer = setTimer(() => { statusTimer = null; start(); }, Math.max(1, Number(d.retry_after)) * 1000);
            return;
        }
        if (r.status === 503) {
            setState('error', { title: 'The browser could not be started', text: 'The server could not start a browser session. Try again in a little while.' });
            return;
        }
        setState('error');
    }

    // Reconnect after a lost connection: look at the session first, never start a new one on its own.
    async function resume() {
        cancelTimers();
        dropConnection();
        const myGen = generation;
        setState('reconnecting');
        const cur = await api('GET', '/api/rbrowser/session');
        if (myGen !== generation) return;
        if (cur.status === 401) { goLogin(); return; }
        if (cur.status === 403) { setState('not_allowed'); return; }
        if (cur.ok) { attach(cur.data); return; }
        if (cur.status === 409) { setState('elsewhere'); return; }
        if (cur.status === 404) {
            const st = await api('GET', '/api/rbrowser/status');
            if (myGen !== generation) return;
            const boot = st.ok && typeof st.data.boot_id === 'string' ? st.data.boot_id : '';
            const seen = storeGet(BOOT_KEY);
            forgetBoot();
            if (seen && boot && seen !== boot) setState('restarted');
            else setState('ended', { text: END_FALLBACK });
            return;
        }
        scheduleReconnect();
    }

    function scheduleReconnect() {
        dropConnection();
        if (reconnectTry >= RECONNECT_DELAYS_MS.length) {
            setState('lost');
            return;
        }
        const delay = RECONNECT_DELAYS_MS[reconnectTry];
        reconnectTry++;
        setState('reconnecting', { text: 'The connection was lost. Trying again (attempt ' + reconnectTry + ' of ' + RECONNECT_DELAYS_MS.length + ').' });
        clearTimer(reconnectTimer);
        reconnectTimer = setTimer(() => { reconnectTimer = null; resume(); }, delay);
    }

    // ---- attach ----
    function attach(info) {
        if (!info || typeof info.ws !== 'string' || info.ws.indexOf(WS_PREFIX) !== 0) {
            setState('error', { text: 'The server sent an unusable session.' });
            return;
        }
        session = info;
        if (typeof info.clipboard === 'string') clipMode = normaliseClip(info.clipboard);
        serverTyping = info.type_text === true;
        rememberBoot();
        applyDeadlines(info, env.now());
        applyClipboardUi();
        connectSocket();
    }

    function connectSocket() {
        dropConnection();
        const myGen = generation;
        const myConn = { closed: false };
        conn = myConn;
        setState('connecting');
        let sock;
        try {
            sock = new env.WebSocket(env.wsUrl(session.ws));
        } catch (e) {
            setState('error', { text: 'The connection could not be opened.' });
            return;
        }
        ws = sock;
        sock.addEventListener('close', (ev) => {
            if (myGen !== generation || myConn.closed) return;
            myConn.closed = true;
            onClose(ev.code, ev.reason);
        });
        let r;
        try {
            r = new env.RFB($('rb-screen'), sock, { credentials: { password: '' } });
        } catch (e) {
            dropConnection();
            setState('error', { text: 'The picture could not be started.' });
            return;
        }
        rfb = r;
        r.scaleViewport = fit;
        r.clipViewport = !fit;
        r.dragViewport = !fit;
        r.resizeSession = false;
        applyQuality();
        r.addEventListener('connect', () => {
            if (myGen !== generation) return;
            reconnectTry = 0;
            lastSize = null;
            setState('connected');
            startPolling();
            scheduleResize(0);
            try { r.focus(); } catch (e) { /* no canvas yet */ }
        });
        r.addEventListener('disconnect', () => {
            // Normally the socket's own close event came first and carried the code. If noVNC gave up without
            // one (a failed handshake), treat it as a lost connection.
            if (myGen !== generation || myConn.closed) return;
            myConn.closed = true;
            onClose(1006, '');
        });
    }

    function onClose(code, reason) {
        stopPolling();
        clearTimer(resizeTimer); resizeTimer = null;
        cancelTyping();
        const wasEnding = ending;
        const r = rfb;
        rfb = null; ws = null; conn = null; generation++;
        if (r) { try { r.disconnect(); } catch (e) { /* already closed */ } }
        if (wasEnding) return;     // the End request decides what is shown
        if (code === 4001) { goLogin(); return; }
        if (code === 4003) { setState('not_allowed'); return; }
        if (code === 4004) {
            forgetBoot();
            setState('ended', { text: 'This browser session no longer exists, or it belongs to another sign-in.' });
            return;
        }
        if (code === 4012) { setState('other_window'); return; }
        if (code === 4013) {
            const why = typeof reason === 'string' ? reason : '';
            if (why !== 'slow') forgetBoot();
            const opts = { text: reasonText(why) };
            if (why === 'slow') opts.action = ['Reconnect', 'start'];
            setState('ended', opts);
            return;
        }
        if (code === 4503) { setState('maintenance'); return; }
        if (RECONNECT_CODES.indexOf(code) !== -1) { scheduleReconnect(); return; }
        setState('closed');
    }

    // ---- deadlines, warnings, polling ----
    function applyDeadlines(info, at) {
        idleDeadline = parseDeadline(info.idle_deadline, at);
        maxDeadline = parseDeadline(info.max_deadline, at);
        netWarning = !!info.net_warning;
    }

    function startPolling() {
        stopPolling();
        lastPollAt = env.now();
        pollTimer = setTimer(pollTick, POLL_MS);
        tickTimer = setTimer(secondTick, 1000);
    }

    function stopPolling() {
        clearTimer(pollTimer); pollTimer = null;
        clearTimer(tickTimer); tickTimer = null;
    }

    async function poll() {
        if (polling || state !== 'connected') return;
        polling = true;
        const myGen = generation;
        const r = await api('GET', '/api/rbrowser/session');
        polling = false;
        if (myGen !== generation || state !== 'connected') return;
        lastPollAt = env.now();
        if (r.ok) {
            applyDeadlines(r.data, lastPollAt);
            updateBanners();
        }
    }

    function pollTick() {
        pollTimer = null;
        if (state !== 'connected') return;
        poll();
        pollTimer = setTimer(pollTick, POLL_MS);
    }

    function secondTick() {
        tickTimer = null;
        if (state !== 'connected') return;
        const now = env.now();
        const rem = idleDeadline === null ? null : (idleDeadline - now) / 1000;
        // Entering the warning window, or inside it: ask the server for the real deadline, because key and
        // pointer activity move it and this page cannot see them.
        if (rem !== null && rem <= IDLE_WARN_S + 5 && now - lastPollAt >= (rem <= IDLE_WARN_S ? POLL_WARN_MS : FRESH_MS)) poll();
        updateBanners();
        tickTimer = setTimer(secondTick, 1000);
    }

    function updateBanners() {
        const now = env.now();
        const fresh = now - lastPollAt < FRESH_MS;
        const idleRem = idleDeadline === null ? null : Math.max(0, Math.ceil((idleDeadline - now) / 1000));
        const idleOn = idleRem !== null && idleRem <= IDLE_WARN_S && fresh && now >= suppressIdleUntil;
        show('rb-banner-idle', idleOn);
        if (idleOn) setText('rb-banner-idle-text', 'Still there? This session ends in ' + idleRem + ' seconds because it is idle.');
        const lifeRem = maxDeadline === null ? null : Math.max(0, Math.ceil((maxDeadline - now) / 60000));
        const lifeOn = lifeRem !== null && (maxDeadline - now) / 1000 <= LIFETIME_WARN_S;
        show('rb-banner-life', lifeOn);
        if (lifeOn) setText('rb-banner-life-text', 'This session reaches its time limit in about ' + Math.max(1, lifeRem) + ' minutes. Save what you need.');
        show('rb-banner-traffic', netWarning);
        if (netWarning) setText('rb-banner-traffic-text', 'This session has used most of its data allowance and ends when it is used up.');
    }

    function imHere() {
        if (!ws || state !== 'connected') return;
        try { ws.send(JSON.stringify({ op: 'here' })); } catch (e) { return; }
        suppressIdleUntil = env.now() + 4000;
        lastPollAt = 0;
        show('rb-banner-idle', false);
        setTimer(() => { poll(); }, 1000);
    }

    // ---- size ----
    function measure() {
        const stage = $('rb-stage');
        let w = stage && stage.clientWidth;
        let h = stage && stage.clientHeight;
        if (!w || !h) { w = (win && win.innerWidth) || MIN_W; h = (win && win.innerHeight) || MIN_H; }
        // A stage narrower than the smallest remote window (a phone held upright): the picture is scaled down to fit the
        // width, so the remote window is asked for with the stage's own shape, not with its height in pixels, or the
        // scaled picture would leave an empty band above and below.
        if (w < MIN_W) { h = h * MIN_W / w; w = MIN_W; }
        return clampSize(w, h);
    }

    function scheduleResize(delay) {
        clearTimer(resizeTimer);
        resizeTimer = setTimer(() => { resizeTimer = null; sendResize(); }, delay === undefined ? RESIZE_DEBOUNCE_MS : delay);
    }

    async function sendResize() {
        if (state !== 'connected' || kbOpen) return;
        const size = measure();
        if (lastSize && lastSize.width === size.width && lastSize.height === size.height) return;
        lastSize = size;
        // A refusal (the limiter allows one a second) or a failure is ignored: the picture is scaled.
        await api('POST', '/api/rbrowser/session/resize', { width: size.width, height: size.height });
    }

    // ---- quality, fit, fullscreen ----
    function qualityById(id) {
        for (const q of QUALITY_LEVELS) if (q.id === id) return q;
        return null;
    }

    function applyQuality() {
        const q = qualityById(quality) || qualityById(DEFAULT_QUALITY);
        if (rfb && q) {
            rfb.qualityLevel = q.quality;
            rfb.compressionLevel = q.compression;
        }
    }

    function setQuality(id) {
        if (!qualityById(id)) return;
        quality = id;
        storeSet(QUALITY_KEY, id);
        applyQuality();
    }

    function setFit(on) {
        fit = !!on;
        if (rfb) {
            rfb.scaleViewport = fit;
            rfb.clipViewport = !fit;
            rfb.dragViewport = !fit;
        }
        setText('rb-fit', fit ? 'Fit' : '1:1');
        const b = $('rb-fit');
        if (b) {
            b.setAttribute('aria-pressed', fit ? 'true' : 'false');
            b.title = fit ? 'Fit the picture to this window. Click for 1:1.' : '1:1 (drag to move the picture). Click to fit.';
        }
    }

    function fullscreenSupported() {
        return !!(doc && (doc.fullscreenEnabled || doc.webkitFullscreenEnabled));
    }

    function toggleFullscreen() {
        const root = doc.documentElement;
        const on = doc.fullscreenElement || doc.webkitFullscreenElement;
        const nav = env.navigator;
        if (on) {
            if (doc.exitFullscreen) doc.exitFullscreen();
            else if (doc.webkitExitFullscreen) doc.webkitExitFullscreen();
            if (nav && nav.keyboard && nav.keyboard.unlock) { try { nav.keyboard.unlock(); } catch (e) { /* not supported */ } }
            return;
        }
        let p;
        if (root.requestFullscreen) p = root.requestFullscreen();
        else if (root.webkitRequestFullscreen) p = root.webkitRequestFullscreen();
        // Where supported, keep the browser from taking Ctrl+W, Ctrl+T and the like.
        if (nav && nav.keyboard && nav.keyboard.lock) {
            Promise.resolve(p).then(() => nav.keyboard.lock()).then(null, () => {});
        }
    }

    // ---- End session ----
    function askEnd() {
        if (ending || endBusy || state === 'init') return;
        asking = { at: env.now() };
        show('rb-end', false);
        setText('rb-confirm-msg', '');
        show('rb-confirm-msg', false);
        show('rb-confirm', true);
    }

    function cancelEnd() {
        if (endBusy) return;
        asking = null;
        show('rb-confirm', false);
        show('rb-end', state === 'connected' || state === 'reconnecting');
    }

    async function confirmEnd(ev) {
        if (!asking || endBusy || (ev && ev.detail > 1) || env.now() - asking.at < CONFIRM_DELAY_MS) return;
        endBusy = true;
        ending = true;
        const yes = $('rb-end-yes');
        const no = $('rb-end-no');
        if (yes) yes.disabled = true;
        if (no) no.disabled = true;
        const r = await api('DELETE', '/api/rbrowser/session');
        endBusy = false;
        if (yes) yes.disabled = false;
        if (no) no.disabled = false;
        if (r.ok || r.status === 404) {
            asking = null;
            show('rb-confirm', false);
            cancelTimers();
            dropConnection();
            forgetBoot();
            session = null;
            ending = false;
            setState('ended', { text: END_REASONS.closed });
            return;
        }
        if (r.status === 401) { goLogin(); return; }
        ending = false;
        setText('rb-confirm-msg', 'The session could not be ended. Try again.');
        show('rb-confirm-msg', true);
        if (!ws && !rfb && state === 'connected') resume();
    }

    // ---- typing ----
    function cancelTyping() {
        clearTimer(typeTimer); typeTimer = null;
        typing = false;
        const q = typeQueue;
        typeQueue = [];
        for (const job of q) job.resolve({ ok: false, reason: 'cancelled', sent: job.idx });
        const rq = routeQueue;                         // a request already sent goes on in the unit; the ones behind it do not start
        routeQueue = [];
        for (const job of rq) job.resolve({ ok: false, reason: 'cancelled', sent: 0 });
    }

    // The answer to something typed or copied. It goes into the text panel; when that panel is shut (a paste on the
    // picture, the phone keyboard) the panel's line is not on the screen, so the same words also show as a banner
    // on the picture for a few seconds.
    function say(text) {
        setText('rb-text-msg', text);
        const panel = $('rb-textpanel');
        if (state === 'connected' && panel && panel.hidden) {
            setText('rb-banner-msg-text', text);
            show('rb-banner-msg', true);
            clearTimer(noteTimer);
            noteTimer = setTimer(() => { noteTimer = null; show('rb-banner-msg', false); }, NOTE_SHOW_MS);
        }
    }

    // ---- text through the server (1.26.3): the unit types it itself, so any character types, not only those of the keyboard table ----
    function routeAllowed(opts) {
        return serverTyping && clipMode !== 'off' && !typing && !typeQueue.length;
    }

    function enqueueRoute(job) {
        return new Promise((resolve) => {
            job.resolve = resolve;
            routeQueue.push(job);
            if (!routing) pumpRoute();
        });
    }

    async function pumpRoute() {
        routing = true;
        try {
            while (routeQueue.length) {
                const first = routeQueue[0];
                if (first.keys) {                       // a key (Backspace, Enter of the phone field): in order, behind the text before it
                    routeQueue.shift();
                    first.resolve(await enqueueKeys(first.keys));
                    continue;
                }
                const batch = [];                       // the text jobs at the head join into one request, never above TYPE_MAX_CHARS characters
                let total = 0;
                while (routeQueue.length && !routeQueue[0].keys && (!batch.length || (!routeQueue[0].release && !batch[0].release && total + routeQueue[0].n <= TYPE_MAX_CHARS))) {
                    total += routeQueue[0].n;
                    batch.push(routeQueue.shift());
                }
                await runRouteBatch(batch);
            }
        } finally {
            routing = false;
        }
    }

    const HELD_ADVICE = 'Characters may be missing or wrong, and a held key may have triggered a shortcut in the remote browser. Check the remote page before you send the text again.';
    const WARN_TEXT = 'A key was held down or Caps Lock changed while the text was typed. ' + HELD_ADVICE;

    async function runRouteBatch(batch) {
        const text = batch.map((j) => j.text).join('');
        if (batch[0].release && rfb) for (const k of MODIFIER_KEYSYMS) rfb.sendKey(k, null, false);
        let r, d, waited = 0;
        for (;;) {
            r = await api('POST', '/api/rbrowser/session/type', { text: text });
            d = r.data || {};
            if (r.status !== 429) break;
            // 429: another text of the session is still being typed (busy) or too many requests (rate). Nothing of this text was typed, and a
            // text before it may still be at work (after a lost answer, for one), so the text is never sent as keys: the route is asked again for a while.
            const ms = d.busy === true ? ROUTE_BUSY_RETRY_MS : ROUTE_RATE_RETRY_MS;
            if (waited + ms > ROUTE_RETRY_MAX_MS || state !== 'connected') {
                for (const j of batch) {
                    if (!j.said) { say(d.busy === true ? 'Another text is still being typed. Send this one again when it is done.' : 'Too much text was sent in a short time. Send it again in a moment.'); j.said = true; }
                    j.resolve({ ok: false, reason: d.busy === true ? 'busy' : 'rate', sent: 0, skipped: j.skipped });
                }
                return;
            }
            await new Promise((resolve) => setTimer(resolve, ms));
            waited += ms;
        }
        const typed = typeof d.typed === 'number' ? d.typed : 0;
        if (typed === 0 && (r.status === 403 || r.status === 404 || d.fallback === true)) {
            serverTyping = false;                       // the server or the unit cannot type text: key events for the rest of the session
            for (const j of batch) j.resolve(await enqueueKeys(j.fkeys, { releaseModifiers: j.release, skipped: j.skipped }));
            return;
        }
        const maintenance = r.status === 503 && d.maintenance === true;
        const unknown = typed === 0 && (r.status === 0 || r.status >= 500) && !maintenance;     // every 5xx but maintenance: the unit may have typed
        let left = typed;
        let said = false;
        for (const j of batch) {
            const n = j.fkeys.length;
            if (r.ok && (d.complete === true || left >= n)) {
                left -= n;
                if (d.warn && !said) { say(WARN_TEXT); said = true; }
                j.resolve({ ok: true, sent: n, skipped: j.skipped, warn: d.warn || '' });
            } else {
                const part = Math.max(0, Math.min(n, left));
                left -= part;
                if (!j.said) {
                    say(unknown ? 'The text may have been typed, in part or in full. Check before sending it again.'
                        : d.why === 'capslock' ? 'Caps Lock is on and could not be switched off, so nothing was typed. Switch it off and send the text again.'
                        : d.why === 'modifier' ? 'Only ' + part + ' of ' + n + ' characters were typed: a key was held down. ' + HELD_ADVICE
                        : part ? 'Only ' + part + ' of ' + n + ' characters were typed.' : 'The text could not be typed.');
                    j.said = true;
                }
                j.resolve({ ok: false, reason: d.why === 'capslock' ? 'capslock' : 'failed', sent: part, skipped: j.skipped });
            }
        }
    }

    function enqueueKeys(keys, opts) {
        opts = opts || {};
        return new Promise((resolve) => {
            typeQueue.push({ keys: keys, idx: 0, resolve: resolve, release: !!opts.releaseModifiers, skipped: opts.skipped || 0, });
            pumpTyping();
        });
    }

    function pumpTyping() {
        if (typing || !typeQueue.length) return;
        typing = true;
        typeStep();
    }

    function typeStep() {
        typeTimer = null;
        const job = typeQueue[0];
        if (!job) { typing = false; return; }
        if (!rfb || state !== 'connected') {
            typing = false;
            cancelTyping();
            return;
        }
        // A held Ctrl repeats its key-down on some systems and noVNC forwards each one: release again per chunk.
        if (job.release) for (const k of MODIFIER_KEYSYMS) rfb.sendKey(k, null, false);
        const end = Math.min(job.keys.length, job.idx + TYPE_CHUNK);
        for (let i = job.idx; i < end; i++) rfb.sendKey(job.keys[i], null);
        job.idx = end;
        if (job.idx >= job.keys.length) {
            typeQueue.shift();
            job.resolve({ ok: true, sent: job.keys.length, skipped: job.skipped });
            if (typeQueue.length) typeStep(); else typing = false;
            return;
        }
        typeTimer = setTimer(typeStep, TYPE_INTERVAL_MS);
    }

    // Types text into the remote browser as key events. Resolves { ok, reason?, sent, skipped }.
    function typeText(text, opts) {
        const chars = Array.from(String(text == null ? '' : text));
        if (chars.length > TYPE_MAX_CHARS) {
            say('That is too much text: at most ' + TYPE_MAX_CHARS + ' characters can be typed at a time. Nothing was sent.');
            return Promise.resolve({ ok: false, reason: 'too_long', sent: 0, skipped: 0 });
        }
        if (!rfb || state !== 'connected') {
            say('The browser is not connected, so nothing was typed.');
            return Promise.resolve({ ok: false, reason: 'not_connected', sent: 0, skipped: 0 });
        }
        const m = keysymsForText(chars.join(''));
        if (!m.keys.length) return Promise.resolve({ ok: true, sent: 0, skipped: m.skipped });
        if (routeAllowed(opts) || (serverTyping && clipMode !== 'off' && (routing || routeQueue.length))) {
            return enqueueRoute({ text: chars.join(''), n: chars.length, fkeys: m.keys, skipped: m.skipped, release: !!(opts && opts.releaseModifiers) });
        }
        return enqueueKeys(m.keys, { releaseModifiers: opts && opts.releaseModifiers, skipped: m.skipped });
    }

    function sendSpecial(keysym) {
        if (!rfb || state !== 'connected') return Promise.resolve({ ok: false, reason: 'not_connected', sent: 0, skipped: 0 });
        if (routing || routeQueue.length) return enqueueRoute({ keys: [keysym] });
        return enqueueKeys([keysym]);
    }

    // ---- paste: Ctrl+V / Cmd+V on the page types the clipboard text ----
    function isOwnField(t) {
        return !!t && (t === $('rb-textbox') || t === $('rb-kbd'));
    }

    function insideScreen(t) {
        const screen = $('rb-screen');
        for (let n = t; n; n = n.parentNode) if (n === screen) return true;
        return false;
    }

    function onKeydownCapture(e) {
        if (clipMode === 'off') return;        // paste-as-typing is off: Ctrl+V is an ordinary key for the remote browser
        if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
        const isV = e.code === 'KeyV' || String(e.key || '').toLowerCase() === 'v';
        if (!isV) return;
        if (state !== 'connected' || isOwnField(e.target) || !insideScreen(e.target)) return;
        // Keep the key from noVNC, but leave the key's default alone so the browser runs its paste.
        e.stopPropagation();
    }

    function onPaste(e) {
        if (clipMode === 'off' || state !== 'connected' || isOwnField(e.target)) return;
        const t = e.target;
        const tag = t && t.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
        const text = e.clipboardData ? e.clipboardData.getData('text/plain') : '';
        e.preventDefault();
        if (text) typeText(text, { releaseModifiers: true });
    }

    // ---- the phone keyboard: a hidden textarea that the Keyboard button focuses ----
    function onKbdKeydown(e) {
        if (composing || e.isComposing || e.keyCode === 229) return;
        if (e.ctrlKey || e.metaKey || e.altKey) return;
        const k = Object.prototype.hasOwnProperty.call(SPECIAL_KEYS, e.key) ? SPECIAL_KEYS[e.key] : 0;
        if (!k) return;
        e.preventDefault();
        sendSpecial(k);
    }

    function handleInputKind(type, data, dataTransfer) {
        if (type === 'insertText' || type === 'insertReplacementText') {
            if (data) typeText(data);
            return true;
        }
        if (type === 'insertFromPaste' || type === 'insertFromDrop') {
            if (clipMode === 'off') { say('Pasting is switched off on this server. Type the text instead.'); return true; }
            const text = data || (dataTransfer && dataTransfer.getData ? dataTransfer.getData('text/plain') : '');
            if (text) typeText(text);
            return true;
        }
        if (type === 'deleteContentBackward') { sendSpecial(KEY_BACKSPACE); return true; }
        if (type === 'insertLineBreak' || type === 'insertParagraph') { sendSpecial(KEY_RETURN); return true; }
        return false;
    }

    function onKbdBeforeInput(e) {
        if (composing || e.isComposing) return;
        if (handleInputKind(e.inputType, e.data, e.dataTransfer)) {
            e.preventDefault();
        }
    }

    function onKbdInput(e) {
        if (composing || e.isComposing) return;     // never touch the field under an input method
        // With beforeinput the work was done there (and a cancelled beforeinput makes no input event at all).
        // Only a browser without beforeinput types from here.
        if (!useBeforeInput && e.inputType !== 'insertCompositionText' && e.inputType !== 'insertFromComposition') {
            handleInputKind(e.inputType, e.data, e.dataTransfer);
        }
        clearKbd();
    }

    function clearKbd() {
        const k = $('rb-kbd');
        if (k && k.value) k.value = '';
    }

    function onCompositionEnd(e) {
        composing = false;
        if (e && e.data) typeText(e.data);
        clearKbd();
    }

    function toggleKeyboard() {
        const k = $('rb-kbd');
        if (!k) return;
        if (kbOpen) { k.blur(); return; }
        k.focus();
    }

    // ---- text box and copying from the browser ----
    function clearReceived() {
        received = '';
        setText('rb-received', '');
        show('rb-received-wrap', false);
    }

    function applyClipboardUi() {
        show('rb-get-clip', clipMode === 'both');
        if (clipMode !== 'both') clearReceived();
        if (clipMode === 'off') {
            show('rb-text-toggle', false);
            show('rb-textpanel', false);
            const b = $('rb-text-toggle');
            if (b) b.setAttribute('aria-expanded', 'false');
        }
    }

    async function sendTextBox() {
        if (clipMode === 'off') return;
        const box = $('rb-textbox');
        if (!box || !box.value) return;
        const r = await typeText(box.value);
        if (r.ok) {
            if (!r.warn) say('Sent ' + r.sent + ' characters.' + (r.skipped ? ' ' + r.skipped + ' could not be typed.' : ''));
            box.value = '';
        } else if (r.reason === 'cancelled') {
            say('The connection closed before all the text was typed.');
        }
    }

    // "Copy from the browser": asks the server for the remote clipboard text. The text is shown, never kept anywhere
    // but the box (and the variable behind the Copy button), and never logged.
    async function copyFromBrowser() {
        if (clipMode !== 'both' || clipBusy || state !== 'connected') return;
        clipBusy = true;
        const btn = $('rb-get-clip');
        if (btn) btn.disabled = true;
        const myGen = generation;
        let r;
        try {
            r = await api('POST', '/api/rbrowser/session/clipboard', {});
        } finally {
            clipBusy = false;
            if (btn) btn.disabled = false;
        }
        if (myGen !== generation || state !== 'connected') return;     // the session ended or reconnected meanwhile
        if (r.status === 401) { goLogin(); return; }
        if (r.status === 403) { say('Copying from the browser is switched off on this server.'); return; }
        if (r.status === 429) { say('Too many copy requests. Wait a moment and try again.'); return; }
        const d = r.data || {};
        if (!r.ok || typeof d.text !== 'string') { say('The text could not be copied from the browser. Try again.'); return; }
        received = d.text;
        setText('rb-received', received);
        show('rb-received-wrap', !!received);
        if (!received) say('There is no text copied in the browser.');
        else if (d.truncated === true) say('The text was longer than ' + CLIPBOARD_MAX + ' bytes and was cut.');
        else say('Text copied from the browser.');
    }

    async function copyReceived() {
        if (!received) return;
        const c = env.clipboard;
        if (c && c.writeText) {
            try { await c.writeText(received); say('Copied.'); return; } catch (e) { /* fall through */ }
        }
        say('Copying is not available in this browser. Select the text and copy it yourself.');
    }

    function toggleTextPanel() {
        const panel = $('rb-textpanel');
        if (!panel || clipMode === 'off') return;
        const on = !!panel.hidden;
        show('rb-textpanel', on);
        if (on) hideNote();
        const b = $('rb-text-toggle');
        if (b) b.setAttribute('aria-expanded', on ? 'true' : 'false');
    }

    function toggleAbout() {
        const panel = $('rb-about-panel');
        if (!panel) return;
        const on = !!panel.hidden;
        show('rb-about-panel', on);
        const b = $('rb-about');
        if (b) b.setAttribute('aria-expanded', on ? 'true' : 'false');
    }

    // ---- wiring ----
    function on(id, type, fn, capture) {
        const el = $(id);
        if (el) el.addEventListener(type, fn, capture);
    }

    function wire() {
        const saved = storeGet(QUALITY_KEY);
        if (saved && qualityById(saved)) quality = saved;
        const sel = $('rb-quality');
        if (sel) {
            for (const q of QUALITY_LEVELS) {
                const o = doc.createElement('option');
                o.value = q.id;
                o.textContent = q.label;
                sel.appendChild(o);
            }
            sel.value = quality;
            sel.addEventListener('change', () => setQuality(sel.value));
        }
        setFit(true);
        on('rb-action', 'click', () => runAction('rb_action'));
        on('rb-action2', 'click', () => runAction('rb_action2'));
        on('rb-here', 'click', imHere);
        on('rb-fit', 'click', () => setFit(!fit));
        on('rb-fullscreen', 'click', toggleFullscreen);
        on('rb-keyboard', 'click', toggleKeyboard);
        on('rb-text-toggle', 'click', toggleTextPanel);
        on('rb-about', 'click', toggleAbout);
        on('rb-about-close', 'click', toggleAbout);
        on('rb-end', 'click', askEnd);
        on('rb-end-no', 'click', cancelEnd);
        on('rb-end-yes', 'click', confirmEnd);
        on('rb-send-text', 'click', sendTextBox);
        on('rb-get-clip', 'click', copyFromBrowser);
        on('rb-copy', 'click', copyReceived);
        const k = $('rb-kbd');
        if (k) {
            k.addEventListener('keydown', onKbdKeydown);
            useBeforeInput = 'onbeforeinput' in k;
            if (useBeforeInput) k.addEventListener('beforeinput', onKbdBeforeInput);
            k.addEventListener('input', onKbdInput);
            k.addEventListener('compositionstart', () => { composing = true; });
            k.addEventListener('compositionend', onCompositionEnd);
            k.addEventListener('focus', () => { kbOpen = true; });
            k.addEventListener('blur', () => { kbOpen = false; scheduleResize(); });
        }
        doc.addEventListener('keydown', onKeydownCapture, true);
        doc.addEventListener('paste', onPaste);
        if (win && win.addEventListener) {
            win.addEventListener('resize', () => scheduleResize());
            win.addEventListener('orientationchange', () => scheduleResize());
        }
    }

    wire();

    return {
        start: start,
        typeText: typeText,
        dispose: function () { cancelTimers(); dropConnection(); },
        get state() { return state; },
        get session() { return session; },
        get quality() { return quality; },
        get fit() { return fit; },
        get received() { return received; },
        get clipMode() { return clipMode; },
    };
}

globalThis.PortalRbrowser = {
    create: create, clampSize: clampSize, keysymFor: keysymFor, keysymsForText: keysymsForText,
    colourToHex: colourToHex, readTheme: readTheme, parseDeadline: parseDeadline, reasonText: reasonText, normaliseClip: normaliseClip,
    QUALITY_LEVELS: QUALITY_LEVELS, DEFAULT_QUALITY: DEFAULT_QUALITY, MIN_W: MIN_W,
    TYPE_CHUNK: TYPE_CHUNK, TYPE_INTERVAL_MS: TYPE_INTERVAL_MS, TYPE_MAX_CHARS: TYPE_MAX_CHARS,
    END_REASONS: END_REASONS,
};

if (typeof document !== 'undefined' && document.getElementById && document.getElementById('rb-app')) {
    let storage = null;
    try { storage = window.localStorage; } catch (e) { storage = null; }
    const app = create({
        doc: document,
        win: window,
        fetch: (url, init) => window.fetch(url, init),
        WebSocket: window.WebSocket,
        RFB: RFB,
        storage: storage,
        setTimeout: (f, ms) => window.setTimeout(f, ms),
        clearTimeout: (t) => window.clearTimeout(t),
        now: () => Date.now(),
        clipboard: window.navigator.clipboard || null,
        navigator: window.navigator,
        location: window.location,
        wsUrl: (path) => (window.Portal && window.Portal.getWebSocketUrl)
            ? window.Portal.getWebSocketUrl(path)
            : (window.location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + window.location.host + path,
    });
    window.addEventListener('beforeunload', () => app.dispose());
    app.start();
}

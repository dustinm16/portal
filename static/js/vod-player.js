/**
 * Open Relay Portal - VOD player
 * Plays one chunk of the member's own VODs in the browser (the portal remuxes it to MP4 first),
 * with previous / next chunk, speed, picture in picture and a resume position per chunk.
 * "Whole session" mode plays all chunks of the folder as one timeline (an HLS playlist the portal writes,
 * through the hls.js copy the live page loads, natively on Safari), with seeking across the session and a
 * resume position per session; a chunk that is not playable, or no HLS support, falls back to chunk by chunk.
 * Opened from My VODs as /vods/play?name=<path as My VODs lists it>[&mode=session].
 */
(function () {
    'use strict';

    const POS_PREFIX = 'vodpos:';
    const POS_MAX_KEYS = 300;
    const SPEED_KEY = 'vodspeed';
    const POLL_START_MS = 1500;
    const POLL_MAX_MS = 4000;
    const POLL_LIMIT_MS = 20 * 60 * 1000;
    const MODE_KEY = 'vodmode';
    const SESSION_POS_PREFIX = POS_PREFIX + 'session:';
    // hls.js: the portal holds a segment request for up to 55 seconds while it prepares the chunk and
    // then answers 503 with Retry-After; keep waiting for that long and retry the 503 many times.
    const HLS_CONFIG = {
        fragLoadPolicy: { default: {
            maxTimeToFirstByteMs: 75000,
            maxLoadTimeMs: 300000,
            timeoutRetry: { maxNumRetry: 6, retryDelayMs: 0, maxRetryDelayMs: 0 },
            errorRetry: { maxNumRetry: 40, retryDelayMs: 2000, maxRetryDelayMs: 5000, backoff: 'linear' },
        } },
        manifestLoadPolicy: { default: {
            maxTimeToFirstByteMs: 20000,
            maxLoadTimeMs: 40000,
            timeoutRetry: { maxNumRetry: 2, retryDelayMs: 0, maxRetryDelayMs: 0 },
            errorRetry: { maxNumRetry: 3, retryDelayMs: 2000, maxRetryDelayMs: 5000, backoff: 'linear' },
        } },
    };

    const params = new URLSearchParams(location.search);
    const name = params.get('name') || '';
    const autoplay = params.get('autoplay') === '1';

    const el = (id) => document.getElementById(id);
    const video = el('vp-video');
    const statusBox = el('vp-status');
    const messageEl = el('vp-message');
    const spinner = el('vp-spinner');
    const actions = el('vp-status-actions');
    const retryBtn = el('vp-retry');

    const folder = name.indexOf('/') >= 0 ? name.slice(0, name.lastIndexOf('/')) : '';
    let mode = 'chunk';
    let hls = null;
    let hlsRecoveries = 0;
    let siblings = [];
    let index = -1;
    let pollTimer = null;
    let generation = 0;

    function enc(path) {
        return path.split('/').map(encodeURIComponent).join('/');
    }

    function playUrl() { return '/api/vods/play/' + enc(name) + '.mp4'; }
    function statusUrl() { return '/api/vods/play-status/' + enc(name) + '.mp4'; }
    function downloadUrl() { return '/api/vods/download/' + enc(name); }
    function sessionUrl() { return '/api/vods/session/' + enc(folder) + '/index.m3u8'; }
    function posKey() { return mode === 'session' ? SESSION_POS_PREFIX + folder : POS_PREFIX + name; }

    function showStatus(text, opts) {
        opts = opts || {};
        video.style.display = 'none';
        statusBox.style.display = 'block';
        messageEl.textContent = text;
        spinner.style.display = opts.busy ? 'block' : 'none';
        actions.style.display = opts.retry ? 'flex' : 'none';
    }

    function showVideo() {
        statusBox.style.display = 'none';
        video.style.display = 'block';
    }

    // ---- resume position -------------------------------------------------------------------

    function readPos() {
        try {
            const raw = localStorage.getItem(posKey());
            if (!raw) return 0;
            const data = JSON.parse(raw);
            return data && typeof data.t === 'number' ? data.t : 0;
        } catch (e) {
            return 0;
        }
    }

    function prunePositions() {
        try {
            const keys = [];
            for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                if (k && k.indexOf(POS_PREFIX) === 0) keys.push(k);
            }
            if (keys.length <= POS_MAX_KEYS) return;
            const dated = keys.map((k) => {
                let at = 0;
                try { at = JSON.parse(localStorage.getItem(k)).at || 0; } catch (e) { /* unreadable: oldest */ }
                return [k, at];
            }).sort((a, b) => a[1] - b[1]);
            dated.slice(0, keys.length - POS_MAX_KEYS).forEach((pair) => localStorage.removeItem(pair[0]));
        } catch (e) { /* storage unavailable */ }
    }

    let lastSaved = 0;
    function savePos(force) {
        const now = Date.now();
        if (!force && now - lastSaved < 5000) return;
        lastSaved = now;
        try {
            if (video.currentTime > 5 && !video.ended) {
                localStorage.setItem(posKey(), JSON.stringify({ t: Math.floor(video.currentTime), at: now }));
                prunePositions();
            }
        } catch (e) { /* storage full or blocked: resume is a convenience only */ }
    }

    function clearPos() {
        try { localStorage.removeItem(posKey()); } catch (e) { /* ignore */ }
    }

    // ---- loading ---------------------------------------------------------------------------

    function stopPolling() {
        generation += 1;
        if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    }

    function destroyHls() {
        if (hls) {
            try { hls.destroy(); } catch (e) { /* already gone */ }
            hls = null;
        }
    }

    function startVideo() {
        stopPolling();
        showVideo();
        video.src = playUrl();
        video.load();
        if (autoplay) {
            const p = video.play();
            if (p && p.catch) p.catch(() => { /* the browser wants a tap first */ });
        }
    }

    async function pollStatus(gen, startedAt, delay) {
        if (gen !== generation) return;
        if (Date.now() - startedAt > POLL_LIMIT_MS) {
            showStatus('Preparing the video is taking too long. You can download the chunk instead.', { retry: true });
            return;
        }
        try {
            const resp = await Portal.fetch(statusUrl());
            if (gen !== generation) return;
            const body = await resp.json().catch(() => ({}));
            if (resp.status === 404) {
                showStatus('This VOD was not found.');
                return;
            }
            if (!resp.ok) {
                showStatus(body.error || 'The video cannot be played right now. You can download the chunk instead.', { retry: true });
                return;
            }
            if (body.state === 'ready') { startVideo(); return; }
            if (body.state === 'unplayable') {
                showStatus(body.message || 'This chunk cannot be played in the browser. Download it instead.');
                return;
            }
            if (body.state === 'failed') {
                showStatus(body.error || 'The chunk could not be prepared.', { retry: true });
                return;
            }
            if (body.state === 'idle') { loadChunk(); return; }       // the job is gone: ask again
            const stage = { waiting: 'Waiting for room', pulling: 'Fetching the chunk from your storage',
                remuxing: 'Converting', probing: 'Checking the file', queued: 'Waiting for its turn' }[body.stage];
            showStatus('Preparing the video' + (stage ? ' (' + stage + ')' : '') + '...', { busy: true });
        } catch (e) {
            if (gen !== generation) return;
            showStatus('Lost contact with the server; trying again...', { busy: true });
        }
        pollTimer = setTimeout(() => pollStatus(gen, startedAt, Math.min(delay * 1.3, POLL_MAX_MS)), delay);
    }

    async function loadChunk() {
        stopPolling();
        destroyHls();
        const gen = generation;
        showStatus('Loading...', { busy: true });
        let resp;
        try {
            // A one byte range request: a cached copy answers 206 at once, anything else answers with
            // JSON (202 preparing, 409, 415, ...) and no video is downloaded.
            resp = await Portal.fetch(playUrl(), { headers: { Range: 'bytes=0-0' } });
        } catch (e) {
            if (gen === generation) showStatus('Could not reach the server.', { retry: true });
            return;
        }
        if (gen !== generation) return;
        if (resp.status === 200 || resp.status === 206) {
            try { if (resp.body && resp.body.cancel) resp.body.cancel(); } catch (e) { /* ignore */ }
            startVideo();
            return;
        }
        const body = await resp.json().catch(() => ({}));
        if (resp.status === 202) {
            pollStatus(gen, Date.now(), POLL_START_MS);
            return;
        }
        if (resp.status === 415) {
            showStatus(body.error || 'This chunk cannot be played in the browser. Download it instead.');
            return;
        }
        if (resp.status === 404) {
            showStatus('This VOD was not found.');
            return;
        }
        if (resp.status === 429) {
            showStatus(body.error || 'Too many chunks are being prepared; wait for one to finish.', { retry: true });
            return;
        }
        showStatus(body.error || 'The video cannot be played right now. You can download the chunk instead.', { retry: true });
    }

    // ---- whole session ---------------------------------------------------------------------

    function canHls() {
        return !!(window.Hls && window.Hls.isSupported && window.Hls.isSupported());
    }

    function canNativeHls() {
        return !!video.canPlayType && video.canPlayType('application/vnd.apple.mpegurl') !== '';
    }

    function fallBackToChunks(why) {
        stopPolling();
        destroyHls();
        setMode('chunk', true);
        Portal.toast(why + ' Playing chunk by chunk instead.', 'info');
        loadChunk();
    }

    function describePlaylist(text) {
        let n = 0;
        let total = 0;
        text.split('\n').forEach((line) => {
            const m = /^#EXTINF:([0-9.]+)/.exec(line);
            if (m) { n += 1; total += parseFloat(m[1]); }
        });
        const mins = Math.round(total / 60);
        return 'Whole session: ' + n + (n === 1 ? ' chunk, ' : ' chunks, ') + mins + ' min';
    }

    function startSession(playlistText) {
        stopPolling();
        showVideo();
        el('vp-pos').textContent = describePlaylist(playlistText || '');
        if (canHls()) {
            hlsRecoveries = 0;
            hls = new window.Hls(HLS_CONFIG);
            hls.on(window.Hls.Events.ERROR, (evt, data) => {
                if (!data || !data.fatal) return;
                const code = data.response && data.response.code;
                if (code === 415) { fallBackToChunks('A chunk of this session cannot be played in the browser.'); return; }
                if (code === 404) { destroyHls(); showStatus('This VOD was not found.'); return; }
                if (data.type === window.Hls.ErrorTypes.NETWORK_ERROR && hlsRecoveries < 3) {
                    hlsRecoveries += 1;
                    hls.startLoad();
                } else if (data.type === window.Hls.ErrorTypes.MEDIA_ERROR && hlsRecoveries < 3) {
                    hlsRecoveries += 1;
                    hls.recoverMediaError();
                } else {
                    fallBackToChunks('The whole session could not be played.');
                }
            });
            hls.loadSource(sessionUrl());
            hls.attachMedia(video);
        } else if (canNativeHls()) {
            video.src = sessionUrl();
            video.load();
        } else {
            fallBackToChunks('This browser cannot play a whole session.');
            return;
        }
        if (autoplay) {
            const p = video.play();
            if (p && p.catch) p.catch(() => { /* the browser wants a tap first */ });
        }
    }

    async function pollSession(gen, startedAt, delay) {
        if (gen !== generation) return;
        if (Date.now() - startedAt > POLL_LIMIT_MS) {
            showStatus('Measuring the session is taking too long.', { retry: true });
            return;
        }
        let resp;
        try {
            resp = await Portal.fetch(sessionUrl());
        } catch (e) {
            if (gen !== generation) return;
            showStatus('Lost contact with the server; trying again...', { busy: true });
            pollTimer = setTimeout(() => pollSession(gen, startedAt, Math.min(delay * 1.3, POLL_MAX_MS)), delay);
            return;
        }
        if (gen !== generation) return;
        if (resp.status === 200) {
            const text = await resp.text().catch(() => '');
            if (gen === generation) startSession(text);
            return;
        }
        const body = await resp.json().catch(() => ({}));
        if (gen !== generation) return;
        if (resp.status === 202) {
            const done = typeof body.done === 'number' && body.total ? ' (' + body.done + ' of ' + body.total + ')' : '';
            showStatus('Measuring the session' + done + '...', { busy: true });
            pollTimer = setTimeout(() => pollSession(gen, startedAt, Math.min(delay * 1.3, POLL_MAX_MS)), delay);
            return;
        }
        if (resp.status === 415) { fallBackToChunks('A chunk of this session cannot be played in the browser.'); return; }
        if (resp.status === 409) { fallBackToChunks('This session is still being recorded.'); return; }
        if (resp.status === 413) { fallBackToChunks('This session is too long for one timeline.'); return; }
        if (resp.status === 404) { showStatus('This VOD was not found.'); return; }
        showStatus(body.error || 'The session cannot be played right now.', { retry: true });
    }

    function loadSession() {
        stopPolling();
        destroyHls();
        const gen = generation;
        showStatus('Loading...', { busy: true });
        pollSession(gen, Date.now(), POLL_START_MS);
    }

    function load() {
        if (mode === 'session') loadSession(); else loadChunk();
    }

    function setMode(next, quiet) {
        mode = next === 'session' && folder ? 'session' : 'chunk';
        try { localStorage.setItem(MODE_KEY, mode); } catch (e) { /* ignore */ }
        const u = new URL(location.href);
        u.searchParams.set('mode', mode);
        try { history.replaceState(null, '', u.pathname + u.search); } catch (e) { /* ignore */ }
        const btn = el('vp-mode');
        btn.textContent = mode === 'session' ? 'Play this chunk only' : 'Play whole session';
        el('vp-prev').style.display = mode === 'session' ? 'none' : '';
        el('vp-next').style.display = mode === 'session' ? 'none' : '';
        if (mode === 'chunk' && index >= 0) {
            el('vp-pos').textContent = 'Chunk ' + (index + 1) + ' of ' + siblings.length;
        }
        if (!quiet) { savePos(true); }
    }

    // ---- previous and next chunk -----------------------------------------------------------

    function go(target, auto) {
        if (!target) return;
        savePos(true);
        location.href = '/vods/play?name=' + encodeURIComponent(target) + (auto ? '&autoplay=1' : '');
    }

    async function loadSiblings() {
        const dir = folder;
        try {
            const resp = await Portal.fetch('/api/vods');
            if (!resp.ok) return;
            const data = await resp.json();
            siblings = (data.files || [])
                .map((f) => f.name)
                .filter((n) => (n.indexOf('/') >= 0 ? n.slice(0, n.lastIndexOf('/')) : '') === dir)
                .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
            index = siblings.indexOf(name);
        } catch (e) { return; }
        if (index >= 0) {
            el('vp-prev').disabled = index === 0;
            el('vp-next').disabled = index === siblings.length - 1;
            if (mode === 'chunk') el('vp-pos').textContent = 'Chunk ' + (index + 1) + ' of ' + siblings.length;
        }
    }

    // ---- start -----------------------------------------------------------------------------

    function init() {
        if (!name) {
            showStatus('No VOD was chosen. Open one from My VODs.');
            return;
        }
        const base = name.split('/').pop();
        el('vp-title').textContent = base;
        el('vp-sub').textContent = name.indexOf('/') >= 0 ? name.slice(0, name.lastIndexOf('/')).split('/').join(' / ') : '';
        document.title = base + ' - VOD Player';
        el('vp-download').href = downloadUrl();

        const speedSel = el('vp-speed');
        let speed = 1;
        try { speed = parseFloat(localStorage.getItem(SPEED_KEY)) || 1; } catch (e) { /* default */ }
        if ([0.5, 0.75, 1, 1.25, 1.5, 2].indexOf(speed) < 0) speed = 1;
        speedSel.value = String(speed);
        video.defaultPlaybackRate = speed;
        speedSel.addEventListener('change', () => {
            const v = parseFloat(speedSel.value) || 1;
            video.defaultPlaybackRate = v;
            video.playbackRate = v;
            try { localStorage.setItem(SPEED_KEY, String(v)); } catch (e) { /* ignore */ }
        });

        const pip = el('vp-pip');
        if (document.pictureInPictureEnabled && video.requestPictureInPicture) {
            pip.style.display = '';
            pip.addEventListener('click', async () => {
                try {
                    if (document.pictureInPictureElement) await document.exitPictureInPicture();
                    else await video.requestPictureInPicture();
                } catch (e) { Portal.toast('Picture in picture is not available now', 'error'); }
            });
        }

        el('vp-prev').addEventListener('click', () => go(siblings[index - 1], false));
        el('vp-next').addEventListener('click', () => go(siblings[index + 1], false));
        retryBtn.addEventListener('click', () => load());

        const modeBtn = el('vp-mode');
        if (folder) {
            let wanted = params.get('mode');
            if (!wanted) { try { wanted = localStorage.getItem(MODE_KEY); } catch (e) { wanted = null; } }
            mode = wanted === 'session' ? 'session' : 'chunk';
            modeBtn.style.display = '';
            modeBtn.addEventListener('click', () => {
                savePos(true);
                setMode(mode === 'session' ? 'chunk' : 'session', true);
                load();
            });
            setMode(mode, true);
        }

        video.addEventListener('loadedmetadata', () => {
            video.playbackRate = parseFloat(speedSel.value) || 1;
            const t = readPos();
            if (t > 5 && video.duration && t < video.duration - 5) video.currentTime = t;
        });
        video.addEventListener('timeupdate', () => savePos(false));
        video.addEventListener('pause', () => savePos(true));
        video.addEventListener('ended', () => {
            clearPos();
            if (mode === 'chunk' && index >= 0 && index < siblings.length - 1) go(siblings[index + 1], true);
        });
        video.addEventListener('error', () => {
            if (mode === 'session') {              // hls.js reports its own errors; a native player is handled here
                if (!hls) fallBackToChunks('The whole session could not be played.');
                return;
            }
            showStatus('The browser could not play this video. You can download the chunk instead.', { retry: true });
        });
        window.addEventListener('pagehide', () => savePos(true));

        fetch('/api/me', { credentials: 'same-origin' }).then((r) => (r.ok ? r.json() : null)).then((me) => {
            if (me && me.username && el('username-display')) el('username-display').textContent = me.username;
        }).catch(() => { /* the name in the navbar is cosmetic */ });

        loadSiblings();
        load();
    }

    document.addEventListener('DOMContentLoaded', init);
})();

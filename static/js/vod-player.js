/**
 * Open Relay Portal - VOD player
 * Plays one chunk of the member's own VODs in the browser (the portal remuxes it to MP4 first),
 * with previous / next chunk, speed, picture in picture and a resume position per chunk.
 * Opened from My VODs as /vods/play?name=<path as My VODs lists it>.
 */
(function () {
    'use strict';

    const POS_PREFIX = 'vodpos:';
    const POS_MAX_KEYS = 300;
    const SPEED_KEY = 'vodspeed';
    const POLL_START_MS = 1500;
    const POLL_MAX_MS = 4000;
    const POLL_LIMIT_MS = 20 * 60 * 1000;

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
            const raw = localStorage.getItem(POS_PREFIX + name);
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
                localStorage.setItem(POS_PREFIX + name, JSON.stringify({ t: Math.floor(video.currentTime), at: now }));
                prunePositions();
            }
        } catch (e) { /* storage full or blocked: resume is a convenience only */ }
    }

    function clearPos() {
        try { localStorage.removeItem(POS_PREFIX + name); } catch (e) { /* ignore */ }
    }

    // ---- loading ---------------------------------------------------------------------------

    function stopPolling() {
        generation += 1;
        if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
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
            if (body.state === 'idle') { load(); return; }       // the job is gone: ask again
            const stage = { waiting: 'Waiting for room', pulling: 'Fetching the chunk from your storage',
                remuxing: 'Converting', probing: 'Checking the file', queued: 'Waiting for its turn' }[body.stage];
            showStatus('Preparing the video' + (stage ? ' (' + stage + ')' : '') + '...', { busy: true });
        } catch (e) {
            if (gen !== generation) return;
            showStatus('Lost contact with the server; trying again...', { busy: true });
        }
        pollTimer = setTimeout(() => pollStatus(gen, startedAt, Math.min(delay * 1.3, POLL_MAX_MS)), delay);
    }

    async function load() {
        stopPolling();
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

    // ---- previous and next chunk -----------------------------------------------------------

    function go(target, auto) {
        if (!target) return;
        savePos(true);
        location.href = '/vods/play?name=' + encodeURIComponent(target) + (auto ? '&autoplay=1' : '');
    }

    async function loadSiblings() {
        const dir = name.indexOf('/') >= 0 ? name.slice(0, name.lastIndexOf('/')) : '';
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
            el('vp-pos').textContent = 'Chunk ' + (index + 1) + ' of ' + siblings.length;
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

        video.addEventListener('loadedmetadata', () => {
            video.playbackRate = parseFloat(speedSel.value) || 1;
            const t = readPos();
            if (t > 5 && video.duration && t < video.duration - 5) video.currentTime = t;
        });
        video.addEventListener('timeupdate', () => savePos(false));
        video.addEventListener('pause', () => savePos(true));
        video.addEventListener('ended', () => {
            clearPos();
            if (index >= 0 && index < siblings.length - 1) go(siblings[index + 1], true);
        });
        video.addEventListener('error', () => {
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

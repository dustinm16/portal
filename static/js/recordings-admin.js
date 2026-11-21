/* Admin > Recordings: list, play, download and delete session recordings.
 *
 * Only administrators get past /api/recordings (anyone else is answered 404), so the tab
 * shows itself only when the list loads. Every row is built with textContent, never markup.
 *
 * The player is small and our own: it reads the asciicast v2 file and writes the output
 * events, at their recorded times, into an xterm.js terminal that takes no input. It
 * replaces asciinema-player, which compiles WebAssembly and so needs 'wasm-unsafe-eval' in
 * the page's script-src; the portal's policy does not allow that.
 */
(function () {
    'use strict';

    const XTERM_JS = '/static/vendor/xterm/xterm.js?v=1';
    const XTERM_CSS = '/static/vendor/xterm/xterm.css?v=1';
    const PAGE = 25;
    const MAX_GAP = 2.0;          // seconds: a long pause in the session is cut to this when playing

    let page = 1;
    let total = 0;

    const $ = (id) => document.getElementById(id);

    function fmtTime(iso) {
        if (!iso) return '';
        const d = new Date(iso);
        return isNaN(d) ? iso : d.toLocaleString();
    }

    function fmtSize(n) {
        if (n < 1024) return n + ' B';
        if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
        return (n / 1048576).toFixed(1) + ' MB';
    }

    function cell(tr, text) {
        const td = document.createElement('td');
        td.textContent = text == null ? '' : String(text);
        tr.appendChild(td);
        return td;
    }

    function query() {
        const p = new URLSearchParams();
        const v = (id) => ($(id).value || '').trim();
        if (v('rec-filter-user')) p.set('user', v('rec-filter-user'));
        if (v('rec-filter-connection')) p.set('connection', v('rec-filter-connection'));
        if (v('rec-filter-from')) p.set('from', v('rec-filter-from'));
        if (v('rec-filter-to')) p.set('to', v('rec-filter-to'));
        p.set('page', String(page));
        p.set('limit', String(PAGE));
        return p.toString();
    }

    async function load() {
        const body = $('rec-body');
        let data;
        try {
            const res = await Portal.fetch('/api/recordings?' + query());
            if (!res.ok) throw new Error('HTTP ' + res.status);
            data = await res.json();
        } catch (e) {
            body.textContent = '';
            const tr = document.createElement('tr');
            const td = cell(tr, 'Could not load the recordings');
            td.colSpan = 7;
            body.appendChild(tr);
            return false;
        }
        total = data.total;
        body.textContent = '';
        if (!data.recordings.length) {
            const tr = document.createElement('tr');
            const td = cell(tr, 'No recordings');
            td.colSpan = 7;
            body.appendChild(tr);
        }
        for (const r of data.recordings) {
            const tr = document.createElement('tr');
            cell(tr, fmtTime(r.started_at));
            cell(tr, r.live ? 'running' : fmtTime(r.ended_at));
            cell(tr, r.user);
            cell(tr, r.connection);
            cell(tr, r.type);
            cell(tr, fmtSize(r.size));
            const actions = document.createElement('td');
            const mk = (label, action) => {
                const b = document.createElement('button');
                b.className = 'range-btn';
                b.type = 'button';
                b.textContent = label;
                b.dataset.action = action;
                b.dataset.id = String(r.id);
                b.dataset.label = (r.user || '') + ' / ' + (r.connection || '');
                actions.appendChild(b);
            };
            mk('Play', 'play');
            mk('Download', 'download');
            if (!r.live) mk('Delete', 'delete');
            tr.appendChild(actions);
            body.appendChild(tr);
        }
        $('rec-count').textContent = total + ' recording' + (total === 1 ? '' : 's');
        const pages = Math.max(1, Math.ceil(total / PAGE));
        $('rec-page-info').textContent = 'Page ' + page + ' of ' + pages;
        $('rec-prev').disabled = page <= 1;
        $('rec-next').disabled = page >= pages;
        return true;
    }

    // ---- the player --------------------------------------------------------------------------

    let term = null;
    let events = [];
    let pos = 0;
    let timer = null;
    let paused = false;
    let castLoaded = null;

    function loadXterm() {
        if (window.Terminal) return Promise.resolve();
        if (castLoaded) return castLoaded;
        castLoaded = new Promise((resolve, reject) => {
            const css = document.createElement('link');
            css.rel = 'stylesheet';
            css.href = XTERM_CSS;
            document.head.appendChild(css);
            const js = document.createElement('script');
            js.src = XTERM_JS;
            js.onload = () => resolve();
            js.onerror = () => { castLoaded = null; reject(new Error('xterm.js did not load')); };
            document.head.appendChild(js);
        });
        return castLoaded;
    }

    function parseCast(text) {
        const lines = text.split('\n').filter((l) => l.length);
        const header = JSON.parse(lines[0]);
        if (header.version !== 2) throw new Error('Not an asciicast v2 file');
        const out = [];
        for (let i = 1; i < lines.length; i++) {
            try {
                const e = JSON.parse(lines[i]);
                if (Array.isArray(e) && typeof e[0] === 'number' && typeof e[1] === 'string') out.push(e);
            } catch (err) { /* a half-written last line of a running session */ }
        }
        return { header, events: out };
    }

    function stopTimer() {
        if (timer !== null) { clearTimeout(timer); timer = null; }
    }

    function status(text) { $('rec-play-status').textContent = text; }

    function apply(e) {
        const kind = e[1];
        if (kind === 'o') {
            term.write(String(e[2]));
        } else if (kind === 'r') {
            const m = /^(\d{1,4})x(\d{1,4})$/.exec(String(e[2]));
            if (m) term.resize(parseInt(m[1], 10), parseInt(m[2], 10));
        } else if (kind === 'm') {
            term.write('\r\n\x1b[33m[' + String(e[2]) + ']\x1b[0m\r\n');
        }
    }

    function step() {
        timer = null;
        if (paused) return;
        if (pos >= events.length) { status('Finished'); $('rec-play-toggle').textContent = 'Replay'; return; }
        apply(events[pos]);
        pos++;
        if (pos >= events.length) { step(); return; }
        const speed = parseFloat($('rec-speed').value) || 1;
        const gap = Math.min(MAX_GAP, Math.max(0, events[pos][0] - events[pos - 1][0]));
        timer = setTimeout(step, Math.max(0, gap * 1000 / speed));
        status('Playing');
    }

    function restart(cols, rows) {
        stopTimer();
        term.reset();
        if (cols && rows) term.resize(cols, rows);
        pos = 0;
        paused = false;
        $('rec-play-toggle').textContent = 'Pause';
        step();
    }

    let headerSize = [80, 24];

    async function play(id, label) {
        $('rec-modal-title').textContent = 'Recording ' + id + ' (' + label + ')';
        $('rec-modal').style.display = '';
        $('rec-player').textContent = '';
        status('Loading');
        try {
            await loadXterm();
            const res = await Portal.fetch('/api/recordings/' + encodeURIComponent(id) + '/cast', { headers: { Accept: '*/*' } });
            if (!res.ok) throw new Error(res.status === 404 ? 'The file is gone' : 'HTTP ' + res.status);
            const cast = parseCast(await res.text());
            events = cast.events;
            headerSize = [cast.header.width || 80, cast.header.height || 24];
            if (term) { term.dispose(); }
            // No input handler is attached and stdin is off: the player never sends anything.
            term = new window.Terminal({
                cols: headerSize[0], rows: headerSize[1], disableStdin: true, cursorBlink: false,
                convertEol: false, scrollback: 5000,
            });
            term.open($('rec-player'));
            restart(headerSize[0], headerSize[1]);
        } catch (e) {
            status('Could not play: ' + e.message);
        }
    }

    function closeModal() {
        stopTimer();
        paused = true;
        $('rec-modal').style.display = 'none';
        if (term) { term.dispose(); term = null; }
        $('rec-player').textContent = '';
    }

    async function remove(id, label) {
        if (!confirm('Delete recording ' + id + ' (' + label + ')? The file is removed and this cannot be undone.')) return;
        try {
            const res = await Portal.fetch('/api/recordings/' + encodeURIComponent(id), { method: 'DELETE' });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);
            Portal.toast('Recording deleted', 'success');
        } catch (e) {
            Portal.toast('Could not delete: ' + e.message, 'error');
        }
        load();
    }

    function bind() {
        const tabBtn = $('tab-btn-recordings');
        if (!tabBtn) return;
        tabBtn.addEventListener('click', (evt) => {
            showTab('recordings', evt);
            page = 1;
            load();
        });
        $('rec-apply').addEventListener('click', () => { page = 1; load(); });
        $('rec-reset').addEventListener('click', () => {
            for (const id of ['rec-filter-user', 'rec-filter-connection', 'rec-filter-from', 'rec-filter-to']) $(id).value = '';
            page = 1;
            load();
        });
        $('rec-prev').addEventListener('click', () => { if (page > 1) { page--; load(); } });
        $('rec-next').addEventListener('click', () => { page++; load(); });
        $('rec-body').addEventListener('click', (evt) => {
            const b = evt.target.closest('button[data-action]');
            if (!b) return;
            const { action, id, label } = b.dataset;
            if (action === 'play') play(id, label);
            else if (action === 'download') window.location.assign('/api/recordings/' + encodeURIComponent(id) + '/cast?download=1');
            else if (action === 'delete') remove(id, label);
        });
        $('rec-modal-close').addEventListener('click', closeModal);
        $('rec-modal-backdrop').addEventListener('click', closeModal);
        $('rec-play-toggle').addEventListener('click', () => {
            if (!term) return;
            if (pos >= events.length) { restart(headerSize[0], headerSize[1]); return; }
            paused = !paused;
            $('rec-play-toggle').textContent = paused ? 'Resume' : 'Pause';
            if (paused) { stopTimer(); status('Paused'); } else { step(); }
        });
        $('rec-restart').addEventListener('click', () => { if (term) restart(headerSize[0], headerSize[1]); });
        // The tab is shown only when the list opens for this account (administrators).
        Portal.fetch('/api/recordings?limit=1').then((res) => {
            if (res.ok) { tabBtn.style.display = ''; }
        }).catch(() => { /* not an administrator: the tab stays hidden */ });
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
    else bind();
    window.RecordingsAdmin = { load, parseCast };
})();

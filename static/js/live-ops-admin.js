/* Admin > Live streams: the streams that are live now, with two actions per stream.
 *
 * "Stop relays" stops that stream's relays only. "End now" disconnects the publisher and ends the
 * session (optionally replacing the stream key so the encoder cannot reconnect with the old one).
 * Both ask first, on their own row below the stream, never under the button that was clicked; the
 * confirm button ignores a click within CONFIRM_DELAY_MS of the question opening and the second
 * click of a double click, and every action is refused while another request is in flight. The refresh
 * every REFRESH_MS does not redraw the table while a question is open; it only updates the figures in place.
 *
 * Only administrators get past /api/admin/live-streams (anyone else is answered 404), so the tab
 * shows itself only when the list loads. Every cell is built with textContent.
 */
(function () {
    'use strict';

    var CONFIRM_DELAY_MS = 600;
    var REFRESH_MS = 5000;

    function el(tag, props, children) {
        var node = document.createElement(tag);
        props = props || {};
        Object.keys(props).forEach(function (k) {
            if (k === 'text') node.textContent = props[k];
            else if (k === 'class') node.className = props[k];
            else if (k === 'on') Object.keys(props.on).forEach(function (ev) { node.addEventListener(ev, props.on[ev]); });
            else node.setAttribute(k, props[k]);
        });
        (children || []).forEach(function (c) { if (c) node.appendChild(c); });
        return node;
    }

    function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

    function formatDuration(s) {
        if (typeof s !== 'number' || !isFinite(s) || s < 0) return '';
        var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
        return h ? h + ' h ' + m + ' min' : m + ' min ' + Math.floor(s % 60) + ' s';
    }

    function formatRate(bps) {
        if (typeof bps !== 'number') return 'not collected';
        return bps >= 1000000 ? (bps / 1000000).toFixed(2) + ' Mbit/s' : Math.round(bps / 1000) + ' kbit/s';
    }

    /* What the confirmation says. The chat line is true of every end of a stream: the live state of the stream's
     * own chat ends and, as at any stream end, its messages are cleared (a chat shared with other streams is kept). */
    function questionText(action, name, regenerate) {
        if (action === 'stop-relays') {
            return 'Stop all relays of "' + name + '"? The stream itself keeps running. The relays stay stopped until the stream ends or the portal is restarted (a restart ends every live session); nothing starts them again before that, and the owner sees them as stopped by an administrator. They start as usual on the next stream.';
        }
        return 'End "' + name + '" now? The publisher is disconnected and the stream goes offline for its viewers. '
            + "The stream chat's live state ends too and, as at any stream end, its messages are cleared. "
            + 'The recording is finished and uploaded as usual; no recording is deleted. '
            + (regenerate
                ? 'The stream key is replaced and temporary publish tokens are revoked, so the encoder cannot reconnect with the old key until the owner copies the new one.'
                : 'The stream key stays as it is, so the encoder can reconnect at once.')
            + ' The owner is told that an administrator ended the stream.';
    }

    function mount(root, api) {
        var state = { rows: [], asking: null, busy: false, loaded: false, timer: null, cells: {} };
        var tbody = root.tbody, note = root.note;

        function visible() { return !(document.hidden === true || document.visibilityState === 'hidden'); }

        function button(text, cls, fn) {
            return el('button', { type: 'button', class: 'range-btn ' + (cls || ''), text: text, on: { click: fn } });
        }

        function ask(id, action) {
            state.asking = { id: id, action: action, at: Date.now(), regenerate: true };
            draw();
        }

        async function run(ev) {
            var a = state.asking;
            if (!a || (ev && ev.detail > 1) || Date.now() - a.at < CONFIRM_DELAY_MS || state.busy) return;
            state.busy = true;
            draw();
            var res, data = {};
            try {
                res = await api(a.action === 'end' ? 'end' : 'stop-relays', a.id, a.action === 'end' ? { confirm: true, regenerate_key: !!a.regenerate } : { confirm: true });
                data = res.data || {};
            } catch (e) {
                res = { ok: false };
            }
            state.busy = false;
            state.asking = null;
            var msg;
            if (!res.ok) msg = 'That did not work' + (data.error ? ': ' + data.error : '');
            else if (a.action === 'end') msg = data.publisher_disconnected
                ? 'The stream was ended and the publisher disconnected.'
                : 'The stream was ended. The publisher was not disconnected' + (data.disconnect_note ? ' (' + data.disconnect_note + ')' : '') + '.';
            else msg = 'Relays stopped: ' + (data.stopped || 0);
            if (window.Portal && Portal.toast) Portal.toast(msg, res.ok ? 'success' : 'error');
            await load();
        }

        function confirmRow(r) {
            var a = state.asking;
            var box = el('div', { class: 'live-ops-confirm', role: 'alert' });
            var text = el('p', { text: questionText(a.action, r.name, a.regenerate) });
            box.appendChild(text);
            if (a.action === 'end') {
                var cb = el('input', { type: 'checkbox', id: 'live-ops-regen' });
                cb.checked = a.regenerate;
                cb.addEventListener('change', function () { a.regenerate = cb.checked; text.textContent = questionText(a.action, r.name, a.regenerate); });
                box.appendChild(el('label', {}, [cb, el('span', { text: ' Replace the stream key and revoke temporary publish tokens' })]));
            }
            var yes = button(a.action === 'end' ? 'Yes, end the stream' : 'Yes, stop the relays', 'live-ops-yes', run);
            if (state.busy) yes.setAttribute('disabled', 'disabled');
            box.appendChild(el('div', {}, [yes, button('Keep it as it is', '', function () { state.asking = null; draw(); })]));
            var td = el('td', { colspan: '8' }, [box]);
            return el('tr', { class: 'live-ops-confirm-row' }, [td]);
        }

        function setFigures(cells, r) {
            cells.uptime.textContent = formatDuration(r.uptime_s);
            cells.bitrate.textContent = formatRate(r.bitrate_bps);
            cells.viewers.textContent = String(r.viewers);
            cells.relays.textContent = String(r.relays_running) + ' running';
            cells.recording.textContent = r.recording ? 'recording' : 'no';
        }

        /* The figures of the rows already on the page, in place and as text only: no row, button or question is
         * rebuilt, so a click that is on its way is not lost. */
        function refreshFigures() {
            state.rows.forEach(function (r) {
                var cells = state.cells[r.id];
                if (cells) setFigures(cells, r);
            });
        }

        function draw() {
            clear(tbody);
            state.cells = {};
            if (state.asking && !state.rows.some(function (r) { return r.id === state.asking.id; })) state.asking = null;
            if (!state.rows.length) {
                tbody.appendChild(el('tr', {}, [el('td', { colspan: '8', text: state.loaded ? 'No stream is live.' : 'Loading' })]));
                return;
            }
            state.rows.forEach(function (r) {
                var acts = el('td', {});
                var busy = state.busy;
                var stopB = button('Stop relays', '', function () { ask(r.id, 'stop-relays'); });
                var endB = button('End now', 'btn-danger', function () { ask(r.id, 'end'); });
                if (busy) { stopB.setAttribute('disabled', 'disabled'); endB.setAttribute('disabled', 'disabled'); }
                acts.appendChild(stopB);
                acts.appendChild(endB);
                var cells = {
                    uptime: el('td', {}), bitrate: el('td', {}), viewers: el('td', {}),
                    relays: el('td', {}), recording: el('td', {})
                };
                state.cells[r.id] = cells;
                setFigures(cells, r);
                var tr = el('tr', {}, [
                    el('td', { text: r.name }), el('td', { text: r.owner }),
                    cells.uptime, cells.bitrate, cells.viewers, cells.relays, cells.recording, acts
                ]);
                tbody.appendChild(tr);
                if (state.asking && state.asking.id === r.id) tbody.appendChild(confirmRow(r));
            });
        }

        async function load() {
            try {
                var res = await api('list');
                if (!res.ok) throw new Error('HTTP');
                state.rows = (res.data && res.data.streams) || [];
                state.loaded = true;
                note.textContent = '';
            } catch (e) {
                note.textContent = 'Could not load the live streams.';
            }
            /* An open question keeps its row and its buttons as they are: the list is read again, but the table is not
             * drawn again until the question is answered or cancelled (a stream that has ended meanwhile closes it, as
             * draw does). The figures of the rows keep moving: only their text is replaced. A stream that started or
             * ended meanwhile appears or goes when the question is closed. */
            if (state.asking && state.rows.some(function (r) { return r.id === state.asking.id; })) { refreshFigures(); return; }
            draw();
        }

        function start() {
            load();
            if (state.timer) clearInterval(state.timer);
            state.timer = setInterval(function () {
                if (visible() && !state.busy && root.isShown()) load();
            }, REFRESH_MS);
        }
        function stop() { if (state.timer) { clearInterval(state.timer); state.timer = null; } }
        return { load: load, start: start, stop: stop, state: state, draw: draw, ask: ask, run: run };
    }

    async function request(kind, id, body) {
        var url = kind === 'list' ? '/api/admin/live-streams' : '/api/admin/streams/' + encodeURIComponent(id) + '/' + kind;
        var opts = kind === 'list' ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) };
        var res = await Portal.fetch(url, opts);
        var data = null;
        try { data = await res.json(); } catch (e) { data = null; }
        return { ok: res.ok, status: res.status, data: data };
    }

    function bind() {
        var tabBtn = document.getElementById('tab-btn-livestreams');
        var tbody = document.getElementById('live-ops-body');
        if (!tabBtn || !tbody) return;
        var tab = document.getElementById('tab-livestreams');
        var ctl = mount({
            tbody: tbody, note: document.getElementById('live-ops-note'),
            isShown: function () { return tab.classList.contains('active'); }
        }, request);
        tabBtn.addEventListener('click', function (evt) {
            showTab('livestreams', evt);
            ctl.start();
        });
        // The tab is shown only when the list opens for this account (administrators).
        Portal.fetch('/api/admin/live-streams').then(function (res) {
            if (res.ok) tabBtn.style.display = '';
            // Only the status is wanted: the body is let go, or the request stays open and the page never becomes idle.
            try {
                var rest = res.body && typeof res.body.cancel === 'function' ? res.body.cancel() : null;
                if (rest && typeof rest.catch === 'function') rest.catch(function () { /* already closed */ });
            } catch (e) { /* nothing to let go */ }
        }).catch(function () { /* not an administrator: the tab stays hidden */ });
    }

    var api = { mount: mount, questionText: questionText, CONFIRM_DELAY_MS: CONFIRM_DELAY_MS };
    if (typeof window !== 'undefined') window.LiveOpsAdmin = api;
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (typeof document !== 'undefined') {
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
        else bind();
    }
})();

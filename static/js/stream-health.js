/* Stream health panel for the streamer (and administrators) on the watch page.
 *
 * Shows what the server receives from the encoder: current bitrate, a sparkline of the last samples,
 * uptime, source and codecs, relays, the recorder and the warnings the server computed. The data
 * comes from GET /api/streams/{id}/health, which answers 404 to everybody but the owner and
 * administrators; the button is only shown to those two and the server decides again on every read.
 *
 * Polling: only while the panel is open and the tab is visible. Every piece of server text goes
 * through textContent; the sparkline is built with DOM calls (no library, no markup strings).
 */
(function () {
    'use strict';

    var POLL_MS = 4000;
    var SVG_NS = 'http://www.w3.org/2000/svg';

    function el(tag, props, children) {
        var node = document.createElement(tag);
        props = props || {};
        Object.keys(props).forEach(function (k) {
            if (k === 'text') node.textContent = props[k];
            else if (k === 'class') node.className = props[k];
            else if (k === 'on') Object.keys(props.on).forEach(function (ev) { node.addEventListener(ev, props.on[ev]); });
            else if (k === 'style') Object.keys(props.style).forEach(function (s) { node.style[s] = props.style[s]; });
            else node.setAttribute(k, props[k]);
        });
        (children || []).forEach(function (c) { if (c) node.appendChild(c); });
        return node;
    }

    function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

    function formatRate(bps) {
        if (typeof bps !== 'number' || !isFinite(bps)) return 'no number yet';
        if (bps >= 1000000) return (bps / 1000000).toFixed(2) + ' Mbit/s';
        return Math.round(bps / 1000) + ' kbit/s';
    }

    function formatDuration(s) {
        if (typeof s !== 'number' || !isFinite(s) || s < 0) return 'unknown';
        var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60);
        if (h) return h + ' h ' + m + ' min';
        if (m) return m + ' min ' + sec + ' s';
        return sec + ' s';
    }

    function formatBytes(n) {
        if (typeof n !== 'number' || n < 1024) return (n || 0) + ' B';
        if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
        if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
        return (n / 1073741824).toFixed(2) + ' GB';
    }

    var RELAY_STATE = { running: 'running', failed: 'failing', idle: 'not running', disabled: 'switched off',
        stopped_by_admin: 'stopped by an administrator' };
    var RECORDER_STATE = {
        recording: 'recording', ending: 'finishing', failed: 'ended with an error',
        stopped_by_guard: 'stopped by the disk guard', refused_by_guard: 'not started (disk guard)',
        not_recording: 'not recording'
    };

    /* The sparkline: an SVG polyline of the samples (oldest first), scaled to the largest sample. */
    function sparkline(samples, width, height) {
        var svg = document.createElementNS(SVG_NS, 'svg');
        svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
        svg.setAttribute('width', String(width));
        svg.setAttribute('height', String(height));
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', 'Bitrate the server receives, last samples');
        var vals = (samples || []).map(function (s) { return Math.max(0, Number(s && s.bps) || 0); });
        if (vals.length < 2) return svg;
        var max = Math.max.apply(null, vals) || 1;
        var step = width / (vals.length - 1);
        var pts = vals.map(function (v, i) {
            return (i * step).toFixed(1) + ',' + (height - 2 - (v / max) * (height - 4)).toFixed(1);
        });
        var line = document.createElementNS(SVG_NS, 'polyline');
        line.setAttribute('points', pts.join(' '));
        line.setAttribute('fill', 'none');
        line.setAttribute('stroke', 'currentColor');
        line.setAttribute('stroke-width', '2');
        svg.appendChild(line);
        return svg;
    }

    function row(label, value) {
        return el('div', { class: 'stream-health-row' }, [
            el('span', { class: 'stream-health-label', text: label + ': ' }),
            el('span', { text: value })
        ]);
    }

    function render(body, data) {
        clear(body);
        if (!data.live) {
            body.appendChild(el('p', { text: 'The stream is not live. The health numbers appear while you are streaming.' }));
            return;
        }
        var ing = data.ingest || {};
        var warns = data.warnings || [];
        var wbox = el('div', { class: 'stream-health-warnings', role: 'status' });
        if (warns.length) {
            warns.forEach(function (w) { wbox.appendChild(el('p', { class: 'stream-health-warning stream-health-' + String(w.level).replace(/[^a-z]/g, ''), text: String(w.text) })); });
        } else {
            wbox.appendChild(el('p', { text: 'No warnings.' }));
        }
        body.appendChild(wbox);
        body.appendChild(row('Uptime', formatDuration(data.uptime_s)));
        if (ing.available) {
            body.appendChild(row('Bitrate', formatRate(ing.bitrate_bps)));
            var chart = el('div', { class: 'stream-health-chart' });
            chart.appendChild(sparkline(ing.samples, 280, 60));
            chart.appendChild(el('div', { class: 'stream-health-caption', text: 'What the server receives' }));
            body.appendChild(chart);
            body.appendChild(row('Source', ing.source || 'unknown'));
            body.appendChild(row('Codecs', (ing.codecs || []).join(', ') || 'unknown'));
            body.appendChild(row('Last data', formatDuration(ing.last_data_age_s) + ' ago'));
        } else {
            body.appendChild(row('Incoming data', String(ing.reason || 'not available')));
        }
        body.appendChild(el('h4', { text: 'Relays' }));
        if (!(data.relays || []).length) body.appendChild(el('p', { text: 'No relays.' }));
        (data.relays || []).forEach(function (r) {
            var line = String(r.name || r.platform || 'relay') + ': ' + (RELAY_STATE[r.state] || String(r.state));
            if (r.last_error) line += ' (' + r.last_error + ')';
            body.appendChild(el('p', { class: 'stream-health-relay', text: line }));
        });
        body.appendChild(el('h4', { text: 'Recording' }));
        var rec = data.recorder || {};
        var rline = RECORDER_STATE[rec.state] || String(rec.state || 'unknown');
        if (rec.state === 'recording' || rec.waiting_chunks) {
            rline += '; ' + (rec.waiting_chunks || 0) + ' finished chunk(s) waiting to upload (' + formatBytes(rec.waiting_bytes) + ')';
        }
        if (rec.last_error) rline += ' (' + rec.last_error + ')';
        body.appendChild(el('p', { text: rline }));
        if (data.load_average) body.appendChild(row('Server load', data.load_average.join(' ')));
        body.appendChild(el('p', { class: 'stream-health-caption', text: 'The server reads the incoming numbers about every 30 seconds, so the graph has one point per 30 seconds, and "no data" is only reported after 75 seconds without growth.' }));
    }

    function mount(opts) {
        var button = opts.button, streamId = Number(opts.streamId);
        var open = false, timer = null, inflight = false, stopped = false;
        var panel = el('aside', { class: 'stream-health-panel', role: 'complementary', 'aria-label': 'Stream health',
            style: { display: 'none', position: 'fixed', top: '4rem', right: '1rem', width: '22rem', maxWidth: '92vw',
                     maxHeight: '80vh', overflowY: 'auto', zIndex: '1000', padding: '0.8rem',
                     background: 'var(--card-bg, #1f2937)', border: '1px solid var(--card-border, #374151)', borderRadius: '8px' } });
        var head = el('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } }, [
            el('strong', { text: 'Stream health' }),
            el('button', { type: 'button', class: 'btn btn-sm btn-secondary', text: 'Close', on: { click: function () { setOpen(false); } } })
        ]);
        var body = el('div', { class: 'stream-health-body' });
        panel.appendChild(head);
        panel.appendChild(body);
        document.body.appendChild(panel);

        function visible() { return !(document.hidden === true || document.visibilityState === 'hidden'); }

        async function refresh() {
            if (!open || inflight || stopped || !visible()) return;
            inflight = true;
            try {
                var res = await Portal.fetch('/api/streams/' + streamId + '/health');
                if (res.status === 404) {
                    stopped = true;
                    clear(body);
                    body.appendChild(el('p', { text: 'Stream health is not available for this account.' }));
                    return;
                }
                if (res.status === 429) {
                    clear(body);
                    body.appendChild(el('p', { text: 'Too many requests. Trying again shortly.' }));
                    return;
                }
                if (!res.ok) throw new Error('HTTP ' + res.status);
                render(body, await res.json());
            } catch (e) {
                clear(body);
                body.appendChild(el('p', { text: 'The health numbers could not be loaded.' }));
            } finally {
                inflight = false;
            }
        }

        function setOpen(v) {
            open = !!v;
            panel.style.display = open ? 'block' : 'none';
            if (button && button.setAttribute) button.setAttribute('aria-expanded', open ? 'true' : 'false');
            if (timer) { clearInterval(timer); timer = null; }
            if (open) {
                refresh();
                timer = setInterval(refresh, POLL_MS);
            }
        }

        document.addEventListener('visibilitychange', function () { if (open && visible()) refresh(); });
        if (button) button.addEventListener('click', function () { setOpen(!open); });
        return { open: function () { setOpen(true); }, close: function () { setOpen(false); }, refresh: refresh,
                 isOpen: function () { return open; }, panel: panel };
    }

    var api = { mount: mount, sparkline: sparkline, render: render, formatRate: formatRate,
                formatDuration: formatDuration, POLL_MS: POLL_MS };
    if (typeof window !== 'undefined') window.StreamHealth = api;
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
})();

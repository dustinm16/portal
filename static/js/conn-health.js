/**
 * Status dots on the dashboard cards (connection health checks, 1.22.0).
 *
 * The server answers GET /api/connections/status with {connection id: {status, latency_ms,
 * since}} for the connections the member can reach, and with {} while the feature is off. This file
 * polls it every 60 seconds while the tab is visible (and once when the tab comes back after a
 * pause), and puts a small dot on each card the answer names. Nothing from the answer is put on the
 * page as markup: the dot's text is its title and aria-label, set as attributes.
 *
 * ConnOrganiser.buildCard asks for a dot with ConnHealth.dot(id) when it draws a card; after each
 * answer the cards already on the page are updated in place. The pure part (describing an entry)
 * has no DOM and is also run under Node by tests/conn_health_harness.js.
 */
(function (root) {
    'use strict';

    var POLL_MS = 60000;
    var MIN_GAP_MS = 30000;   // a tab that becomes visible again refreshes if the answer is older than this
    var STATUSES = { up: 1, down: 1, unknown: 1, maintenance: 1 };

    function statusOf(entry) {
        return entry && STATUSES[entry.status] ? entry.status : 'unknown';
    }

    function formatSince(iso) {
        var d = new Date(iso);
        if (!iso || isNaN(d.getTime())) return '';
        return d.toLocaleString();
    }

    /** The words of the tooltip: "up, 12 ms", "down since 6/1/2030, 4:05:00 PM", "status unknown" */
    function describe(entry) {
        var s = statusOf(entry);
        if (s === 'up') {
            var ms = entry && typeof entry.latency_ms === 'number' ? entry.latency_ms : null;
            return ms === null ? 'up' : 'up, ' + Math.round(ms) + ' ms';
        }
        if (s === 'down') {
            var since = formatSince(entry && entry.since);
            return since ? 'down since ' + since : 'down';
        }
        if (s === 'maintenance') return 'in maintenance';
        return 'status unknown';
    }

    var core = { statusOf: statusOf, describe: describe, formatSince: formatSince, POLL_MS: POLL_MS };
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = core;
    }
    if (typeof document === 'undefined') return;

    var map = {};            // connection id -> entry (an empty map: the feature is off, no dots)
    var timer = null;
    var lastAt = 0;
    var inFlight = false;

    function paint(span, id) {
        var entry = map[id];
        var s = statusOf(entry);
        var text = describe(entry);
        span.className = 'conn-health-dot conn-health-' + s;
        span.setAttribute('data-conn-health', s);
        span.setAttribute('title', text);
        span.setAttribute('aria-label', 'Connection status: ' + text);
    }

    function makeDot(id) {
        var span = document.createElement('span');
        span.setAttribute('role', 'img');
        span.setAttribute('data-health-for', id);
        paint(span, id);
        return span;
    }

    /** A dot for the card of connection `id`, or null when the answer does not name it. */
    function dot(id) {
        ensureStarted();
        return Object.prototype.hasOwnProperty.call(map, id) ? makeDot(id) : null;
    }

    function applyAll() {
        var cards = document.querySelectorAll('.connection-card[data-conn-id]');
        for (var i = 0; i < cards.length; i++) {
            var card = cards[i];
            var id = card.getAttribute('data-conn-id');
            var have = card.querySelector('.conn-health-dot');
            var want = Object.prototype.hasOwnProperty.call(map, id);
            if (have && !want) {
                have.parentNode.removeChild(have);
            } else if (have && want) {
                paint(have, id);
            } else if (!have && want) {
                var host = card.querySelector('h4') || card;
                host.appendChild(makeDot(id));
            }
        }
    }

    async function refresh() {
        if (inFlight) return;
        inFlight = true;
        try {
            var res = await Portal.fetch('/api/connections/status');
            if (res && res.ok) {
                var data = await res.json();
                map = data && typeof data === 'object' && !Array.isArray(data) ? data : {};
                lastAt = Date.now();
                applyAll();
            }
        } catch (e) {
            /* keep the last answer; the next poll tries again */
        } finally {
            inFlight = false;
        }
    }

    function visible() {
        return document.visibilityState === undefined || document.visibilityState === 'visible';
    }

    function ensureStarted() {
        if (timer !== null || typeof Portal === 'undefined' || typeof Portal.fetch !== 'function') return;
        timer = setInterval(function () { if (visible()) refresh(); }, POLL_MS);
        document.addEventListener('visibilitychange', function () {
            if (visible() && Date.now() - lastAt > MIN_GAP_MS) refresh();
        });
        refresh();
    }

    root.ConnHealth = { dot: dot, refresh: refresh, core: core };
})(typeof window !== 'undefined' ? window : globalThis);

/*
 * Chat overlay for an OBS browser source.
 *
 * Reads the overlay token from the URL fragment (never sent to a server), opens /ws/overlay and sends the token in
 * the first frame. Everything from the server is shown through textContent: links are not clickable, nothing in a
 * message is loaded as an image or embed, so OBS never fetches a third-party address because of a message.
 * Fragment options (all optional, validated here): t=TOKEN  size=12..96 (pixels)  lines=1..30  fade=0..600
 * (seconds a line stays; 0 keeps it until it is pushed out).
 */
(function () {
    'use strict';

    var REFUSED = 4401;               // the server's one code for a bad, revoked or regenerated token: do not retry
    var DEFAULTS = { size: 24, lines: 8, fade: 30 };
    var LIMITS = { size: [12, 96], lines: [1, 30], fade: [0, 600] };
    var FADE_MS = 600;

    function clampInt(raw, lo, hi, dflt) {
        if (typeof raw !== 'string' || !/^[0-9]{1,4}$/.test(raw)) return dflt;
        var n = parseInt(raw, 10);
        return n < lo ? lo : (n > hi ? hi : n);
    }

    function parseHash(hash) {
        var out = { token: '', size: DEFAULTS.size, lines: DEFAULTS.lines, fade: DEFAULTS.fade };
        var raw = {};
        String(hash || '').replace(/^#/, '').split('&').forEach(function (pair) {
            var i = pair.indexOf('=');
            if (i > 0) raw[pair.slice(0, i)] = pair.slice(i + 1);
        });
        if (typeof raw.t === 'string' && /^ov_[A-Za-z0-9_-]{43}$/.test(raw.t)) out.token = raw.t;
        out.size = clampInt(raw.size, LIMITS.size[0], LIMITS.size[1], DEFAULTS.size);
        out.lines = clampInt(raw.lines, LIMITS.lines[0], LIMITS.lines[1], DEFAULTS.lines);
        out.fade = clampInt(raw.fade, LIMITS.fade[0], LIMITS.fade[1], DEFAULTS.fade);
        return out;
    }

    function wsUrl(loc) {
        return (loc.protocol === 'https:' ? 'wss://' : 'ws://') + loc.host + '/ws/overlay';
    }

    function Overlay(root, opts, doc, timers) {
        this.root = root;
        this.opts = opts;
        this.doc = doc;
        this.timers = timers;
        this.lines = [];                       // { id, node, timer }
        root.style.setProperty('--overlay-size', opts.size + 'px');
    }

    Overlay.prototype.find = function (id) {
        for (var i = 0; i < this.lines.length; i++) if (this.lines[i].id === id) return this.lines[i];
        return null;
    };

    Overlay.prototype.drop = function (line) {
        var i = this.lines.indexOf(line);
        if (i >= 0) this.lines.splice(i, 1);
        if (line.timer) this.timers.clear(line.timer);
        if (line.node.parentNode) line.node.parentNode.removeChild(line.node);
    };

    Overlay.prototype.fadeOut = function (line) {
        var self = this;
        line.node.className = 'overlay-line overlay-fading';
        line.timer = this.timers.set(function () { self.drop(line); }, FADE_MS);
    };

    Overlay.prototype.add = function (m) {
        if (!m || typeof m.id !== 'number' || this.find(m.id)) return;         // history and live frames can overlap
        var node = this.doc.createElement('div');
        node.className = 'overlay-line';
        if (m.badge === 'owner' || m.badge === 'mod') {
            var badge = this.doc.createElement('span');
            badge.className = 'overlay-badge';
            badge.textContent = m.badge;
            node.appendChild(badge);
        }
        var name = this.doc.createElement('span');
        name.className = 'overlay-name' + (m.badge === 'owner' || m.badge === 'mod' ? ' overlay-badge-' + m.badge : '');
        name.textContent = String(m.name || '');
        var text = this.doc.createElement('span');
        text.className = 'overlay-text';
        text.textContent = String(m.text || '');
        node.appendChild(name);
        node.appendChild(text);
        this.root.appendChild(node);
        var line = { id: m.id, node: node, text: text, timer: null };
        this.lines.push(line);
        while (this.lines.length > this.opts.lines) this.drop(this.lines[0]);
        if (this.opts.fade > 0) {
            var self = this;
            line.timer = this.timers.set(function () { self.fadeOut(line); }, this.opts.fade * 1000);
        }
    };

    Overlay.prototype.remove = function (id) {
        var line = this.find(id);
        if (line) this.drop(line);
    };

    Overlay.prototype.edit = function (id, text) {
        var line = this.find(id);
        if (line) line.text.textContent = String(text || '');
    };

    Overlay.prototype.clear = function () {
        while (this.lines.length) this.drop(this.lines[0]);
    };

    /* One frame from the server. Anything that is not on the list is ignored. */
    Overlay.prototype.handle = function (f) {
        if (!f || typeof f !== 'object') return;
        var self = this;
        if (f.type === 'history' && Array.isArray(f.messages)) {
            f.messages.forEach(function (m) { self.add(m); });
        } else if (f.type === 'message') {
            this.add(f);
        } else if (f.type === 'edit') {
            this.edit(f.id, f.text);
        } else if (f.type === 'delete') {
            this.remove(f.id);
        } else if (f.type === 'prune' && Array.isArray(f.ids)) {
            f.ids.forEach(function (id) { self.remove(id); });
        } else if (f.type === 'clear') {
            this.clear();
        }
    };

    function start(env) {
        var opts = parseHash(env.location.hash);
        var root = env.document.getElementById('overlay-chat');
        if (!root || !opts.token) return null;       // no token in the address: nothing to connect, nothing shown
        var overlay = new Overlay(root, opts, env.document, env.timers);
        var delay = 1000, stopped = false;
        function connect() {
            var ws = new env.WebSocket(wsUrl(env.location));
            ws.onopen = function () { ws.send(JSON.stringify({ type: 'auth', token: opts.token })); };
            ws.onmessage = function (ev) {
                var data;
                try { data = JSON.parse(ev.data); } catch (e) { return; }
                delay = 1000;
                overlay.handle(data);
            };
            ws.onclose = function (ev) {
                if (stopped) return;
                if (ev && ev.code === REFUSED) { stopped = true; overlay.clear(); return; }   // revoked or regenerated: stay quiet
                env.timers.set(connect, delay);
                delay = Math.min(delay * 2, 30000);
            };
        }
        connect();
        return overlay;
    }

    var api = { parseHash: parseHash, Overlay: Overlay, start: start, wsUrl: wsUrl, REFUSED: REFUSED };
    if (typeof window !== 'undefined') {
        window.PortalOverlay = api;
        window.PortalOverlay.run = function () {
            return start({
                location: window.location, document: window.document, WebSocket: window.WebSocket,
                timers: {
                    set: function (f, ms) { return window.setTimeout(f, ms); },
                    clear: function (t) { window.clearTimeout(t); }
                }
            });
        };
        window.PortalOverlay.run();
    }
})();

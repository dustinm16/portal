/* Announcement banners.

   Loaded by portal.js on every signed-in page, and directly by the login page. It fetches the
   active announcements (data-url of its own script tag, default /api/announcements) and shows each
   as a banner at the top of the page. A dismissal is remembered in this browser by announcement id
   and the time of its last change, so an edited announcement shows again.

   The text is plain text with a small safe subset of markup: **bold**, *italic*, `code`,
   [text](link), a bare link and line breaks. Links must be http or https. Everything is built with
   DOM nodes: text goes in as text nodes or textContent, never into markup, so a tag, an event
   handler or a javascript: link in the text is shown as the harmless text it is.

   The same file runs under Node (tests/announce_harness.js) against a small fake document. */
(function (root) {
    'use strict';

    var STORE_KEY = 'portal.announce.dismissed';
    var POLL_MS = 60000;
    var MAX_DEPTH = 3;
    var LEVELS = { info: 1, warning: 1, outage: 1 };
    // Pages whose body cannot scroll (a fixed-height layout, html and body with overflow hidden): the banner floats over
    // the top there instead of pushing the message input or the player controls out of view.
    var OVERLAY_PATHS = /^\/(terminal|vnc|media|spice|proxmox|github|browser|vods\/play|chat|watch)(\/|$)/;

    // A link target: only http and https, as the browser's own URL parser reads it.
    function safeUrl(raw, URLCtor) {
        var U = URLCtor || (typeof URL !== 'undefined' ? URL : null);
        if (!U || typeof raw !== 'string' || raw.length > 2000) return null;
        var u;
        try { u = new U(raw); } catch (e) { return null; }
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
        return u.href;
    }

    var RE_CODE = /`([^`\n]+)`/y;
    var RE_BOLD = /\*\*(?=\S)([^\n]+?)\*\*/y;
    var RE_ITALIC = /\*(?=[^\s*])([^*\n]+?)\*/y;
    var RE_MDLINK = /\[([^\]\n]+)\]\(([^)\s]+)\)/y;
    var RE_BARE = /https?:\/\/[^\s<>"]+/y;

    function matchAt(re, text, i) {
        re.lastIndex = i;
        return re.exec(text);
    }

    // One line of text into a list of nodes: {type:'text', text} {type:'strong'|'em', children}
    // {type:'code', text} {type:'a', href, children}. Anything that is not a complete, valid piece stays text.
    function parseInline(text, depth, URLCtor) {
        var out = [];
        var buf = '';
        var i = 0;
        depth = depth || 0;
        function flush() { if (buf) { out.push({ type: 'text', text: buf }); buf = ''; } }
        while (i < text.length) {
            var ch = text[i];
            var m = null;
            if (ch === '`' && (m = matchAt(RE_CODE, text, i))) {
                flush(); out.push({ type: 'code', text: m[1] }); i += m[0].length; continue;
            }
            if (ch === '*' && depth < MAX_DEPTH && (m = matchAt(RE_BOLD, text, i))) {
                flush(); out.push({ type: 'strong', children: parseInline(m[1], depth + 1, URLCtor) }); i += m[0].length; continue;
            }
            if (ch === '*' && depth < MAX_DEPTH && (m = matchAt(RE_ITALIC, text, i))) {
                flush(); out.push({ type: 'em', children: parseInline(m[1], depth + 1, URLCtor) }); i += m[0].length; continue;
            }
            if (ch === '[' && (m = matchAt(RE_MDLINK, text, i))) {
                var href = safeUrl(m[2], URLCtor);
                if (href) {
                    flush();
                    out.push({ type: 'a', href: href, children: depth < MAX_DEPTH ? parseInline(m[1], depth + 1, URLCtor) : [{ type: 'text', text: m[1] }] });
                    i += m[0].length; continue;
                }
            }
            if ((ch === 'h' || ch === 'H') && (m = matchAt(RE_BARE, text, i))) {
                var url = m[0].replace(/[.,;:!?)\]'"]+$/, '');
                var bare = safeUrl(url, URLCtor);
                if (bare && url.length > 0) {
                    flush();
                    out.push({ type: 'a', href: bare, children: [{ type: 'text', text: url }] });
                    i += url.length; continue;
                }
            }
            buf += ch;
            i += 1;
        }
        flush();
        return out;
    }

    // The whole body: lines separated by {type:'br'}.
    function parse(body, URLCtor) {
        var lines = String(body === null || body === undefined ? '' : body).replace(/\r\n?/g, '\n').split('\n');
        var out = [];
        lines.forEach(function (line, n) {
            if (n > 0) out.push({ type: 'br' });
            Array.prototype.push.apply(out, parseInline(line, 0, URLCtor));
        });
        return out;
    }

    function build(doc, nodes, parent) {
        nodes.forEach(function (n) {
            var el;
            if (n.type === 'text') {
                parent.appendChild(doc.createTextNode(n.text));
            } else if (n.type === 'br') {
                parent.appendChild(doc.createElement('br'));
            } else if (n.type === 'code') {
                el = doc.createElement('code');
                el.textContent = n.text;
                parent.appendChild(el);
            } else if (n.type === 'strong' || n.type === 'em') {
                el = doc.createElement(n.type);
                build(doc, n.children, el);
                parent.appendChild(el);
            } else if (n.type === 'a') {
                el = doc.createElement('a');
                el.setAttribute('href', n.href);
                el.setAttribute('rel', 'noopener noreferrer');
                el.setAttribute('target', '_blank');
                build(doc, n.children, el);
                parent.appendChild(el);
            }
        });
        return parent;
    }

    function renderBody(doc, body, parent, URLCtor) {
        return build(doc, parse(body, URLCtor), parent);
    }

    // ---- dismissal, remembered by id and last change ------------------------------------------------------
    function readDismissed(storage) {
        try {
            var v = JSON.parse(storage.getItem(STORE_KEY) || '{}');
            return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
        } catch (e) { return {}; }
    }
    function writeDismissed(storage, map) {
        try { storage.setItem(STORE_KEY, JSON.stringify(map)); } catch (e) { /* storage full or blocked: not remembered */ }
    }
    function isDismissed(map, a) {
        return Object.prototype.hasOwnProperty.call(map, String(a.id)) && map[String(a.id)] === String(a.updated_at);
    }
    // Entries for announcements that no longer exist are dropped, so the map cannot grow for ever.
    function pruneDismissed(map, items) {
        var keep = {};
        items.forEach(function (a) {
            var k = String(a.id);
            if (Object.prototype.hasOwnProperty.call(map, k)) keep[k] = map[k];
        });
        return keep;
    }
    function visible(items, map) {
        return items.filter(function (a) { return a && typeof a.id !== 'undefined' && !isDismissed(map, a); });
    }

    var CSS = '#portal-announcements{display:flex;flex-direction:column;gap:0}' +
        '#portal-announcements.announce-overlay{position:fixed;top:0;left:0;right:0;z-index:100000;max-height:40vh;overflow-y:auto}' +
        '.announce{display:flex;align-items:flex-start;gap:.75rem;padding:.55rem 1rem;font-size:.9rem;line-height:1.4;' +
        'border-bottom:1px solid rgba(0,0,0,.35);color:#fff;background:#2563eb}' +
        '.announce-warning{background:#b45309}.announce-outage{background:#b91c1c}' +
        '.announce-text{flex:1;min-width:0;overflow-wrap:anywhere}' +
        '.announce a{color:inherit;text-decoration:underline}' +
        '.announce code{background:rgba(0,0,0,.3);padding:0 .3em;border-radius:3px}' +
        '.announce-level{font-weight:700;text-transform:uppercase;font-size:.75rem;letter-spacing:.04em;margin-right:.5rem}' +
        '.announce-close{flex:none;background:rgba(0,0,0,.25);color:inherit;border:1px solid rgba(255,255,255,.5);' +
        'border-radius:4px;padding:.15rem .6rem;cursor:pointer;font:inherit}';

    // Fills `box` with one banner per undismissed announcement. `onDismiss(a)` is called after the button is used.
    function renderBanners(doc, box, items, map, onDismiss, URLCtor) {
        while (box.firstChild) box.removeChild(box.firstChild);
        visible(items, map).forEach(function (a) {
            var level = Object.prototype.hasOwnProperty.call(LEVELS, a.level) ? a.level : 'info';
            var row = doc.createElement('div');
            row.className = 'announce announce-' + level;
            row.setAttribute('role', level === 'outage' ? 'alert' : 'status');
            row.setAttribute('data-announcement-id', String(a.id));
            var text = doc.createElement('div');
            text.className = 'announce-text';
            var tag = doc.createElement('span');
            tag.className = 'announce-level';
            tag.textContent = level;
            text.appendChild(tag);
            renderBody(doc, a.body, text, URLCtor);
            var btn = doc.createElement('button');
            btn.setAttribute('type', 'button');
            btn.className = 'announce-close';
            btn.setAttribute('aria-label', 'Dismiss this announcement');
            btn.textContent = 'Dismiss';
            btn.addEventListener('click', function () { onDismiss(a); });
            row.appendChild(text);
            row.appendChild(btn);
            box.appendChild(row);
        });
        return box;
    }

    function mountBox(doc, win) {
        var box = doc.getElementById('portal-announcements');
        if (box) return box;
        box = doc.createElement('div');
        box.id = 'portal-announcements';
        var login = doc.body.classList && doc.body.classList.contains('login-page');   // a centred flex page: float over it
        if (login || OVERLAY_PATHS.test((win.location && win.location.pathname) || '')) box.className = 'announce-overlay';
        var style = doc.createElement('style');
        style.textContent = CSS;
        doc.head.appendChild(style);
        var body = doc.body;
        body.insertBefore(box, body.firstChild);
        return box;
    }

    // Starts the banners in a page: fetch now, then every minute and when the tab becomes visible again. A hidden tab
    // asks nothing, and after a 401 (signed out) nothing is asked again.
    function start(win, url) {
        var doc = win.document;
        var storage;
        try { storage = win.localStorage; } catch (e) { storage = null; }
        if (!storage) storage = { getItem: function () { return null; }, setItem: function () {} };
        var items = [];
        var box = null;
        function draw() {
            var map = pruneDismissed(readDismissed(storage), items);
            if (!items.length && !box) return;
            box = mountBox(doc, win);
            renderBanners(doc, box, items, map, function (a) {
                var m = readDismissed(storage);
                m[String(a.id)] = String(a.updated_at);
                writeDismissed(storage, m);
                draw();
            });
        }
        var stopped = false;   // set by a 401: the session is over, so nothing more is asked
        var timer = null;
        function load() {
            if (stopped || doc.hidden) return Promise.resolve();   // a hidden tab asks again when it is shown
            return win.fetch(url, { credentials: 'same-origin', cache: 'no-store', headers: { 'Accept': 'application/json' } })
                .then(function (r) {
                    if (r.status === 401) {
                        stopped = true;
                        if (timer !== null && typeof win.clearInterval === 'function') win.clearInterval(timer);
                        return null;
                    }
                    return r.ok ? r.json() : null;
                })
                .then(function (data) {
                    if (!data || !Array.isArray(data.announcements)) return;
                    items = data.announcements;
                    // The sign-in list is a subset of the member list: it must not forget what a member dismissed.
                    if (url.indexOf('/public') < 0) writeDismissed(storage, pruneDismissed(readDismissed(storage), items));
                    draw();
                })
                .catch(function () { /* offline or signed out: leave what is shown */ });
        }
        load();
        timer = win.setInterval(load, POLL_MS);
        doc.addEventListener('visibilitychange', function () { if (!doc.hidden) load(); });
        return { load: load };
    }

    var api = {
        safeUrl: safeUrl, parse: parse, renderBody: renderBody, renderBanners: renderBanners,
        readDismissed: readDismissed, writeDismissed: writeDismissed, isDismissed: isDismissed,
        pruneDismissed: pruneDismissed, visible: visible, start: start, STORE_KEY: STORE_KEY, MAX_DEPTH: MAX_DEPTH
    };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.Announce = api;

    // Run by itself when loaded by a page (not under Node): the address comes from the script tag.
    if (typeof document !== 'undefined' && document.currentScript && !root.__announceStarted) {
        root.__announceStarted = true;
        var url = document.currentScript.getAttribute('data-url') || '/api/announcements';
        var go = function () { start(root, url); };
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', go); else go();
    }
})(typeof window !== 'undefined' ? window : globalThis);

/* Admin > Settings > Web Browser on the server (release 1.25.0).

   One card for the server-side browser (the member's page is static/rbrowser.html):
   - whether the host can run it, what is missing (with the apt line for the packages of a closed table) and
     the Chromium version, with a warning when the binary is older than CHROMIUM_WARN_DAYS;
   - the last sandbox check, each check with its result, and "Run check" (superadmin);
   - the ten settings with their ranges, Save (superadmin, password session) and the effective seats and CPU
     the server will really use;
   - the sessions that are running now: member, since, active or idle, attached, memory, CPU, data in and out,
     with "End" behind a question on its own row.

   Never shown, stored or asked for here: a web address, a page title, a picture, a key, a pointer position or
   clipboard text. The server sends none of them and this script reads only the fields listed in SESSION_FIELDS
   and the other documented ones, so a field that appears one day is not drawn. Every cell and message is built
   with textContent; no HTML string is ever made from an answer. The End and Save buttons ignore a click within
   CONFIRM_DELAY_MS of a question opening, the second click of a double click, and any click while another
   request is in flight. The refresh does not redraw a question that is open or a form that is being edited. */
(function () {
    'use strict';

    var CONFIRM_DELAY_MS = 600;
    var REFRESH_MS = 10000;
    var CHROMIUM_WARN_DAYS = 45;
    var SESSION_FIELDS = ['sid_prefix', 'user_id', 'username', 'started', 'state', 'attached', 'memory_mb', 'cpu_seconds', 'net_in_mb', 'net_out_mb'];

    /* Section 8.1 of the design: key, label, kind and range. */
    var SETTINGS = [
        { key: 'rbrowser_enabled', label: 'Switched on', kind: 'bool', hint: 'Off ends every session and removes the sandbox rules.' },
        { key: 'rbrowser_min_role', label: 'Who may use it', kind: 'choice', values: ['admin', 'moderator', 'user'], hint: 'Raising it ends the sessions of members below it.' },
        { key: 'rbrowser_max_sessions', label: 'Sessions at once', kind: 'int', min: 1, max: 8, hint: '1 to 8; the server may use fewer (see below).' },
        { key: 'rbrowser_idle_minutes', label: 'Idle minutes', kind: 'int', min: 5, max: 120, hint: '5 to 120.' },
        { key: 'rbrowser_memory_mb', label: 'Memory per session (MB)', kind: 'int', min: 1024, max: 4096, hint: '1024 to 4096.' },
        { key: 'rbrowser_cpu_percent', label: 'CPU per session (percent)', kind: 'int', min: 50, max: 400, hint: '50 to 400; the server may use less (see below).' },
        { key: 'rbrowser_clipboard', label: 'Clipboard', kind: 'choice', values: ['both', 'in', 'off'],
          labels: { both: 'Both ways', 'in': 'Into the browser only', off: 'Off' }, hint: 'Both ways, into the browser only (typed text), or off.' },
        { key: 'rbrowser_home_url', label: 'Home page', kind: 'text', max: 300, hint: 'An https address, at most 300 characters.' },
        { key: 'rbrowser_upload_kbps', label: 'Upload limit (kbit/s)', kind: 'int', min: 500, max: 50000, zero: true, hint: '0 for no kernel rule, or 500 to 50000.' },
        { key: 'rbrowser_extra_deny', label: 'Extra blocked networks', kind: 'list', max: 32, hint: 'One CIDR per line, at most 32.' }
    ];

    /* Section 12: the packages, and which binary each one provides. A name the server reports that is not in this
       table is listed but never put into the command. */
    var APT_PACKAGE = {
        chromium: 'chromium', 'chromium-browser': 'chromium', Xvfb: 'xvfb', x11vnc: 'x11vnc', xauth: 'xauth',
        xrandr: 'x11-xserver-utils', 'matchbox-window-manager': 'matchbox-window-manager', iptables: 'iptables'
    };

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

    function isNum(v) { return typeof v === 'number' && isFinite(v); }

    function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

    /* "started" is epoch seconds (design: Session.started is a float); epoch milliseconds and an ISO string are read too. */
    function startedMs(v) {
        if (isNum(v)) return v < 1e11 ? v * 1000 : v;
        if (typeof v === 'string') { var t = Date.parse(v); return isFinite(t) ? t : null; }
        return null;
    }

    function formatAgo(ms, now) {
        if (ms === null) return '';
        var s = Math.max(0, Math.floor((now - ms) / 1000));
        var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
        if (h) return h + ' h ' + m + ' min';
        if (m) return m + ' min';
        return 'less than a minute';
    }

    function formatCpu(sec) {
        if (!isNum(sec) || sec < 0) return '';
        if (sec >= 3600) return (sec / 3600).toFixed(1) + ' h';
        if (sec >= 120) return Math.round(sec / 60) + ' min';
        return Math.round(sec) + ' s';
    }

    function formatMb(v) { return isNum(v) ? (Math.round(v * 10) / 10) + ' MB' : ''; }

    function aptLine(missing) {
        var seen = {}, pkgs = [];
        (missing || []).forEach(function (name) {
            if (typeof name !== 'string' || !Object.prototype.hasOwnProperty.call(APT_PACKAGE, name)) return;
            var p = APT_PACKAGE[name];
            if (!seen[p]) { seen[p] = 1; pkgs.push(p); }
        });
        return pkgs.length ? 'sudo apt-get install -y --no-install-recommends ' + pkgs.join(' ') : '';
    }

    /* Section 8.2: when the portal does not run as root the only reason is that one, and the package line would not
       help, so it is not shown. */
    function notRoot(reasons) {
        return (reasons || []).some(function (r) { return typeof r === 'string' && /not run as root/i.test(r); });
    }

    function questionText(row) {
        var who = row.username ? '"' + row.username + '"' : 'this member';
        return 'End the Web Browser session of ' + who + ' now? Their browser closes at once and nothing in it is kept. '
            + 'They are told that an administrator ended it, and the end is written to the audit log before it happens.';
    }

    /* What the form shows for a stored value. The server's canonical clipboard values are both, in and off; the older name
       to_browser is read as in, so the list never shows a value it cannot offer. */
    function shown(def, v) {
        if (def.key === 'rbrowser_clipboard' && v === 'to_browser') return 'in';
        return v;
    }

    function listText(v) {
        if (Array.isArray(v)) return v.filter(function (x) { return typeof x === 'string'; }).join('\n');
        return typeof v === 'string' ? v : '';
    }

    function listValue(text) {
        return String(text || '').split(/[\s,]+/).filter(function (x) { return x; });
    }

    function mount(root, api) {
        var state = {
            data: null, asking: null, busy: false, loaded: false, timer: null, dirty: false,
            fields: {}, saving: false, checking: false, saveBtn: null, loadError: false
        };
        var note = root.note;

        function say(text, bad) {
            note.textContent = text || '';
            note.setAttribute('class', bad ? 'rbrowser-admin-note rbrowser-admin-bad' : 'rbrowser-admin-note');
        }

        function button(text, cls, fn) {
            return el('button', { type: 'button', class: 'range-btn ' + (cls || ''), text: text, on: { click: fn } });
        }

        function toast(msg, ok) { if (window.Portal && Portal.toast) Portal.toast(msg, ok ? 'success' : 'error'); }

        // ---- availability ----
        function drawAvailability() {
            var box = root.avail, a = (state.data && state.data.availability) || {};
            clear(box);
            var yes = a.available === true;
            box.appendChild(el('p', { class: 'rbrowser-admin-line', text: yes ? 'This server can run the browser.' : 'This server cannot run the browser yet.' }));
            var reasons = Array.isArray(a.reasons) ? a.reasons.filter(function (r) { return typeof r === 'string'; }) : [];
            if (reasons.length) {
                var ul = el('ul', { class: 'rbrowser-admin-list' });
                reasons.forEach(function (r) { ul.appendChild(el('li', { text: r })); });
                box.appendChild(ul);
            }
            var missing = Array.isArray(a.missing) ? a.missing.filter(function (m) { return typeof m === 'string'; }) : [];
            if (missing.length && !notRoot(reasons)) {
                box.appendChild(el('p', { class: 'rbrowser-admin-line', text: 'Missing: ' + missing.join(', ') }));
                var apt = aptLine(missing);
                if (apt) {
                    box.appendChild(el('p', { class: 'rbrowser-admin-line', text: 'On Debian or Ubuntu:' }));
                    box.appendChild(el('code', { class: 'rbrowser-admin-code', text: apt }));
                }
            }
            if (typeof a.chromium_version === 'string' && a.chromium_version) {
                var v = 'Chromium ' + a.chromium_version;
                if (isNum(a.chromium_age_days)) v += ' (the file is ' + plural(Math.floor(a.chromium_age_days), 'day', 'days') + ' old)';
                box.appendChild(el('p', { class: 'rbrowser-admin-line', text: v }));
                if (isNum(a.chromium_age_days) && a.chromium_age_days > CHROMIUM_WARN_DAYS) {
                    box.appendChild(el('p', {
                        class: 'rbrowser-admin-line rbrowser-admin-bad',
                        text: 'This Chromium is older than ' + CHROMIUM_WARN_DAYS + ' days. Update it with apt; a running session keeps the old file until it ends.'
                    }));
                }
            }
            var kernel = a.kernel_upload_limit === true;
            box.appendChild(el('p', {
                class: 'rbrowser-admin-line',
                text: 'Kernel upload limit: ' + (kernel ? 'in force.' : 'not in force (the upload setting is 0, or iptables is missing).')
            }));
        }

        // ---- checks ----
        function drawChecks() {
            var box = root.checks, p = (state.data && state.data.preflight) || null;
            clear(box);
            var head;
            if (!p || !Array.isArray(p.checks) || !p.checks.length) head = 'The sandbox check has not run on this server yet.';
            else head = p.ok === true ? 'The last sandbox check passed.' : 'The last sandbox check failed. The browser stays off until it passes.';
            box.appendChild(el('p', { class: 'rbrowser-admin-line' + (p && p.ok === false ? ' rbrowser-admin-bad' : ''), text: head }));
            if (p && Array.isArray(p.checks) && p.checks.length) {
                var ul = el('ul', { class: 'rbrowser-admin-list' });
                p.checks.forEach(function (c) {
                    if (!c || typeof c !== 'object') return;
                    var line = (c.ok === true ? 'passed' : 'FAILED') + ': ' + String(c.name || '') + (c.detail ? ' - ' + String(c.detail) : '');
                    ul.appendChild(el('li', { class: c.ok === true ? '' : 'rbrowser-admin-bad', text: line }));
                });
                box.appendChild(ul);
            }
            var run = button(state.checking ? 'Checking...' : 'Run check', '', runCheck);
            if (state.checking) run.setAttribute('disabled', 'disabled');
            box.appendChild(run);
        }

        async function runCheck(ev) {
            if ((ev && ev.detail > 1) || state.checking || state.busy) return;
            state.checking = true;
            drawChecks();
            var res = { ok: false }, data = {};
            try { res = await api('preflight'); data = res.data || {}; } catch (e) { res = { ok: false }; }
            state.checking = false;
            if (res.ok && state.data) {
                state.data.preflight = data;
                toast(data.ok === true ? 'The sandbox check passed.' : 'The sandbox check failed.', data.ok === true);
            } else if (res.status === 403) {
                toast('Only a superadmin can run the check.', false);
            } else {
                toast('The check did not run' + (data && data.error ? ': ' + data.error : '') + '.', false);
            }
            drawChecks();
            await load();
        }

        // ---- settings ----
        function drawSeats() {
            var s = (state.data && state.data.seats) || null;
            if (!s || !isNum(s.max) || !isNum(s.cpu_percent)) { root.seats.textContent = ''; return; }
            root.seats.textContent = 'What the server really uses: ' + plural(s.max, 'session', 'sessions') + ' at once, ' + s.cpu_percent
                + ' percent of a CPU each (never more than the settings above; fewer when the machine is small).';
        }

        function fieldValue(def) {
            var f = state.fields[def.key];
            if (!f) return undefined;
            var raw = f.input;
            if (def.kind === 'bool') return !!raw.checked;
            if (def.kind === 'int') { var t = String(raw.value).trim(); return /^-?\d+$/.test(t) ? parseInt(t, 10) : NaN; }
            if (def.kind === 'list') return listValue(raw.value);
            return String(raw.value);
        }

        function sameValue(def, a, b) {
            if (def.kind === 'list') return JSON.stringify(a) === JSON.stringify(listValue(listText(b)));
            return a === b;
        }

        function problem(def, v) {
            if (def.kind === 'int') {
                if (!isNum(v)) return def.label + ' must be a whole number.';
                if (def.zero && v === 0) return '';
                if (v < def.min || v > def.max) return def.label + ' must be ' + (def.zero ? '0 or ' : '') + 'from ' + def.min + ' to ' + def.max + '.';
            }
            if (def.kind === 'text' && v.length > def.max) return def.label + ' is longer than ' + def.max + ' characters.';
            if (def.kind === 'list' && v.length > def.max) return def.label + ' has more than ' + def.max + ' entries.';
            if (def.kind === 'choice' && def.values.indexOf(v) < 0) return def.label + ' is not one of its values.';
            return '';
        }

        function drawSettings() {
            var box = root.settings, cur = (state.data && state.data.settings) || {};
            clear(box);
            state.fields = {};
            var grid = el('div', { class: 'rbrowser-admin-grid' });
            SETTINGS.forEach(function (def) {
                var id = 'rbrowser-set-' + def.key;
                var input, v = shown(def, cur[def.key]);
                if (def.kind === 'bool') {
                    input = el('input', { type: 'checkbox', id: id });
                    input.checked = v === true;
                } else if (def.kind === 'choice') {
                    input = el('select', { id: id }, def.values.map(function (o) { return el('option', { value: o, text: (def.labels && def.labels[o]) || o }); }));
                    input.value = def.values.indexOf(v) >= 0 ? v : def.values[0];
                } else if (def.kind === 'list') {
                    input = el('textarea', { id: id, rows: '3', spellcheck: 'false', autocomplete: 'off' });
                    input.value = listText(v);
                } else if (def.kind === 'text') {
                    input = el('input', { type: 'text', id: id, maxlength: String(def.max), spellcheck: 'false', autocomplete: 'off' });
                    input.value = typeof v === 'string' ? v : '';
                } else {
                    input = el('input', { type: 'number', id: id, min: String(def.zero ? 0 : def.min), max: String(def.max), step: '1' });
                    input.value = isNum(v) ? String(v) : '';
                }
                var markDirty = function () { state.dirty = true; };
                input.addEventListener('input', markDirty);
                input.addEventListener('change', markDirty);
                state.fields[def.key] = { input: input };
                grid.appendChild(el('div', { class: 'rbrowser-admin-field' }, [
                    el('label', { for: id, text: def.label }), input,
                    el('span', { class: 'rbrowser-admin-hint', text: def.hint })
                ]));
            });
            box.appendChild(grid);
            var save = button('Save settings', 'rbrowser-admin-save', saveSettings);
            save.disabled = state.saving;
            state.saveBtn = save;
            box.appendChild(save);
            box.appendChild(el('p', {
                class: 'rbrowser-admin-hint',
                text: 'A change never alters a session that is running, except that switching it off or raising the role ends the sessions affected. Only a superadmin signed in with a password can save.'
            }));
        }

        async function saveSettings(ev) {
            if ((ev && ev.detail > 1) || state.saving || state.busy) return;
            var changes = {}, cur = (state.data && state.data.settings) || {}, bad = '';
            SETTINGS.forEach(function (def) {
                if (bad) return;
                var v = fieldValue(def);
                if (v === undefined) return;
                bad = problem(def, v);
                if (!bad && !sameValue(def, v, shown(def, cur[def.key]))) changes[def.key] = v;
            });
            if (bad) { say(bad, true); return; }
            if (!Object.keys(changes).length) { say('Nothing to save.', false); return; }
            state.saving = true;
            if (state.saveBtn) state.saveBtn.disabled = true;
            var res = { ok: false }, data = {};
            try { res = await api('put', null, changes); data = res.data || {}; } catch (e) { res = { ok: false }; }
            state.saving = false;
            if (state.saveBtn) state.saveBtn.disabled = false;
            if (res.ok) {
                state.dirty = false;
                say('Saved.', false);
                toast('The Web Browser settings are saved.', true);
            } else if (res.status === 403) {
                say('Only a superadmin signed in with a password can change these settings.', true);
            } else {
                say('That did not save' + (data && data.error ? ': ' + data.error : '.'), true);
            }
            await load(res.ok);
        }

        // ---- sessions ----
        function ask(sid) {
            if (state.busy) return;
            state.asking = { sid: sid, at: Date.now() };
            drawSessions();
        }

        async function endNow(ev) {
            var a = state.asking;
            if (!a || (ev && ev.detail > 1) || Date.now() - a.at < CONFIRM_DELAY_MS || state.busy) return;
            state.busy = true;
            drawSessions();
            var res = { ok: false }, data = {};
            try { res = await api('end', a.sid, { confirm: true }); data = res.data || {}; } catch (e) { res = { ok: false }; }
            state.busy = false;
            state.asking = null;
            toast(res.ok ? 'The session was ended.' : 'That did not work' + (data && data.error ? ': ' + data.error : ''), res.ok);
            await load();
        }

        function rows() { return (state.data && Array.isArray(state.data.sessions)) ? state.data.sessions.filter(function (r) { return r && typeof r === 'object'; }) : []; }

        function confirmRow(r) {
            var box = el('div', { class: 'rbrowser-admin-confirm', role: 'alert' });
            box.appendChild(el('p', { text: questionText(r) }));
            var yes = button('Yes, end the session', 'rbrowser-admin-yes', endNow);
            if (state.busy) yes.setAttribute('disabled', 'disabled');
            box.appendChild(el('div', {}, [yes, button('Keep it', '', function () { if (!state.busy) { state.asking = null; drawSessions(); } })]));
            return el('tr', { class: 'rbrowser-admin-confirm-row' }, [el('td', { colspan: '9' }, [box])]);
        }

        function drawSessions() {
            var tbody = root.tbody, list = rows(), now = Date.now();
            clear(tbody);
            if (state.asking && !list.some(function (r) { return r.sid_prefix === state.asking.sid; })) state.asking = null;
            if (!list.length) {
                tbody.appendChild(el('tr', {}, [el('td', { colspan: '9', text: state.loaded ? 'No session is running.' : 'Loading' })]));
                return;
            }
            list.forEach(function (r) {
                var endB = button('End', 'btn-danger', function () { ask(r.sid_prefix); });
                if (state.busy) endB.setAttribute('disabled', 'disabled');
                tbody.appendChild(el('tr', {}, [
                    el('td', { text: typeof r.username === 'string' && r.username ? r.username : (isNum(r.user_id) ? 'user ' + r.user_id : '') }),
                    el('td', { text: formatAgo(startedMs(r.started), now) }),
                    el('td', { text: r.state === 'active' ? 'active' : (r.state === 'idle' ? 'idle' : '') }),
                    el('td', { text: r.attached === true ? 'yes' : (r.attached === false ? 'no' : '') }),
                    el('td', { text: formatMb(r.memory_mb) }),
                    el('td', { text: formatCpu(r.cpu_seconds) }),
                    el('td', { text: formatMb(r.net_in_mb) }),
                    el('td', { text: formatMb(r.net_out_mb) }),
                    el('td', {}, [endB])
                ]));
                if (state.asking && state.asking.sid === r.sid_prefix) tbody.appendChild(confirmRow(r));
            });
        }

        function drawAll() {
            drawAvailability();
            drawChecks();
            drawSeats();
            if (!state.dirty && !state.saving) drawSettings();
            drawSessions();
        }

        async function load(forceForm) {
            var ok = false;
            try {
                var res = await api('get');
                if (!res.ok || !res.data || typeof res.data !== 'object') throw new Error('HTTP');
                state.data = res.data;
                state.loaded = true;
                ok = true;
                if (forceForm === true) state.dirty = false;
                if (state.loadError) { say('', false); state.loadError = false; }
                if (state.asking && !rows().some(function (r) { return r.sid_prefix === state.asking.sid; })) state.asking = null;
            } catch (e) {
                say('Could not load the Web Browser card.', true);
                state.loadError = true;
            }
            if (ok) {
                if (state.asking) {
                    /* a question is open: the sessions stay as they are until it is answered; the rest is read again */
                    drawAvailability(); drawChecks(); drawSeats();
                    if (!state.dirty && !state.saving) drawSettings();
                } else drawAll();
            }
            return ok;
        }

        function start() {
            if (state.timer) clearInterval(state.timer);
            state.timer = setInterval(function () {
                var hidden = document.hidden === true || document.visibilityState === 'hidden';
                if (!hidden && !state.busy && !state.saving && !state.checking && (!root.isShown || root.isShown())) load();
            }, REFRESH_MS);
        }
        function stop() { if (state.timer) { clearInterval(state.timer); state.timer = null; } }

        return { load: load, start: start, stop: stop, state: state, drawAll: drawAll, ask: ask, endNow: endNow, runCheck: runCheck, saveSettings: saveSettings };
    }

    async function request(kind, sid, body) {
        var url = '/api/admin/rbrowser', opts = {};
        if (kind === 'put') opts = { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) };
        else if (kind === 'preflight') { url += '/preflight'; opts = { method: 'POST' }; }
        else if (kind === 'end') {
            url += '/sessions/' + encodeURIComponent(sid) + '/end';
            opts = { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) };
        }
        var res = await Portal.fetch(url, opts);
        var data = null;
        try { data = await res.json(); } catch (e) { data = null; }
        return { ok: res.ok, status: res.status, data: data };
    }

    function bind() {
        var card = document.getElementById('rbrowser-admin-card');
        var tbody = document.getElementById('rbrowser-admin-sessions');
        if (!card || !tbody) return;
        var ctl = mount({
            note: document.getElementById('rbrowser-admin-note'), avail: document.getElementById('rbrowser-admin-avail'),
            checks: document.getElementById('rbrowser-admin-checks'), settings: document.getElementById('rbrowser-admin-settings'),
            seats: document.getElementById('rbrowser-admin-seats'), tbody: tbody,
            isShown: function () { return card.offsetParent !== null; }
        }, request);
        // The card is shown only when the answer opens for this account (administrators).
        ctl.load().then(function (ok) { if (ok) { card.style.display = ''; ctl.start(); } }).catch(function () { /* not an administrator */ });
    }

    var api = {
        mount: mount, questionText: questionText, aptLine: aptLine, notRoot: notRoot, SETTINGS: SETTINGS,
        SESSION_FIELDS: SESSION_FIELDS, CONFIRM_DELAY_MS: CONFIRM_DELAY_MS
    };
    if (typeof window !== 'undefined') window.RbrowserAdmin = api;
    if (typeof document !== 'undefined' && document.getElementById) {
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
        else bind();
    }
})();

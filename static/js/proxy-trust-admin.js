/* Admin > Settings > Shared web connections: the web connections members have shared with others, and whether a
 * superadmin trusts each one (release 1.24.1).
 *
 * A web connection somebody else shared runs in a sandbox that keeps its script away from the viewer's portal
 * session. "Trust" lifts that for one connection (its pages then run on the portal's own address as each person it
 * is shared with); "Remove trust" puts the sandbox back. Both ask first, on their own row below the connection,
 * never under the button that was clicked; the confirm button ignores a click within CONFIRM_DELAY_MS of the
 * question opening and the second click of a double click, and every action is refused while another request is in
 * flight. Only name, owner and the number of people it is shared with are shown: never the host, the port or any
 * stored secret (the route does not send them). The card shows itself only when the list loads (superadmins).
 * Every cell is built with textContent and every handler with addEventListener.
 */
(function () {
    'use strict';

    var CONFIRM_DELAY_MS = 600;

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

    function questionText(action, row) {
        var who = '"' + row.name + '" of ' + row.owner;
        if (action === 'trust') {
            return 'Trust ' + who + '? Its pages will then run on the portal\'s own address, as part of the portal, for every person it is '
                + 'shared with: its script can act as each of them here (read portal pages, use the API as them). Do this only for an application '
                + 'you know and whose owner you trust. The mark ends by itself if the connection\'s host, port or address is changed.';
        }
        return 'Remove the trust mark of ' + who + '? Its pages open sandboxed again for everybody it is shared with, as for any member\'s shared connection.';
    }

    function mount(root, api) {
        var state = { rows: [], asking: null, busy: false, loaded: false };
        var tbody = root.tbody, note = root.note;

        function button(text, cls, fn) {
            return el('button', { type: 'button', class: 'range-btn ' + (cls || ''), text: text, on: { click: fn } });
        }

        function ask(id, action) {
            if (state.busy) return;
            state.asking = { id: id, action: action, at: Date.now() };
            draw();
        }

        async function run(ev) {
            var a = state.asking;
            if (!a || (ev && ev.detail > 1) || Date.now() - a.at < CONFIRM_DELAY_MS || state.busy) return;
            state.busy = true;
            draw();
            var res, data = {};
            try {
                res = await api('set', a.id, a.action === 'trust');
                data = res.data || {};
            } catch (e) {
                res = { ok: false };
            }
            state.busy = false;
            state.asking = null;
            var msg = res.ok
                ? (a.action === 'trust' ? 'The connection is trusted.' : 'The trust mark is removed.')
                : 'That did not work' + (data.error ? ': ' + data.error : '');
            if (window.Portal && Portal.toast) Portal.toast(msg, res.ok ? 'success' : 'error');
            await load();
        }

        function confirmRow(r) {
            var a = state.asking;
            var box = el('div', { class: 'proxy-trust-confirm', role: 'alert' });
            box.appendChild(el('p', { text: questionText(a.action, r) }));
            var yes = button(a.action === 'trust' ? 'Yes, trust it' : 'Yes, remove the mark', 'proxy-trust-yes', run);
            if (state.busy) yes.setAttribute('disabled', 'disabled');
            box.appendChild(el('div', {}, [yes, button('Keep it as it is', '', function () { if (!state.busy) { state.asking = null; draw(); } })]));
            return el('tr', { class: 'proxy-trust-confirm-row' }, [el('td', { colspan: '6' }, [box])]);
        }

        function draw() {
            clear(tbody);
            if (state.asking && !state.rows.some(function (r) { return r.id === state.asking.id; })) state.asking = null;
            if (!state.rows.length) {
                tbody.appendChild(el('tr', {}, [el('td', { colspan: '6', text: state.loaded ? 'No member has shared a web connection.' : 'Loading' })]));
                return;
            }
            state.rows.forEach(function (r) {
                var acts = el('td', {});
                if (r.trusted) {
                    var off = button('Remove trust', '', function () { ask(r.id, 'untrust'); });
                    if (state.busy) off.setAttribute('disabled', 'disabled');
                    acts.appendChild(off);
                } else if (r.browser_mode) {
                    acts.textContent = 'Never (browser mode)';
                } else {
                    var on = button('Trust', '', function () { ask(r.id, 'trust'); });
                    if (state.busy) on.setAttribute('disabled', 'disabled');
                    acts.appendChild(on);
                }
                tbody.appendChild(el('tr', {}, [
                    el('td', { text: r.owner }), el('td', { text: r.name }),
                    el('td', { text: r.browser_mode ? 'Browser mode' : 'Web' }),
                    el('td', { text: String(r.shares) }),
                    el('td', { text: r.trusted ? 'Trusted' : 'Sandboxed' }), acts
                ]));
                if (state.asking && state.asking.id === r.id) tbody.appendChild(confirmRow(r));
            });
        }

        async function load() {
            var ok = false;
            try {
                var res = await api('list');
                if (!res.ok) throw new Error('HTTP');
                var all = (res.data && res.data.connections) || [];
                state.rows = all.filter(function (r) { return r && r.shares > 0; }).sort(function (x, y) {
                    return (x.trusted === y.trusted ? 0 : x.trusted ? 1 : -1) || String(x.owner).localeCompare(String(y.owner)) || String(x.name).localeCompare(String(y.name));
                });
                state.loaded = true;
                ok = true;
                note.textContent = '';
            } catch (e) {
                note.textContent = 'Could not load the shared web connections.';
            }
            /* An open question keeps its row and buttons as they are until it is answered or cancelled. */
            if (state.asking && state.rows.some(function (r) { return r.id === state.asking.id; })) return ok;
            draw();
            return ok;
        }

        return { load: load, state: state, draw: draw, ask: ask, run: run };
    }

    async function request(kind, id, trusted) {
        var res;
        if (kind === 'list') res = await Portal.fetch('/api/admin/proxy-trust-connections');
        else res = await Portal.fetch('/api/admin/connections/' + encodeURIComponent(id) + '/proxy-trust',
            { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ trusted: !!trusted }) });
        var data = null;
        try { data = await res.json(); } catch (e) { data = null; }
        return { ok: res.ok, status: res.status, data: data };
    }

    function bind() {
        var card = document.getElementById('proxy-trust-card');
        var tbody = document.getElementById('proxy-trust-body');
        if (!card || !tbody) return;
        var ctl = mount({ tbody: tbody, note: document.getElementById('proxy-trust-note') }, request);
        // The card is shown only when the list opens for this account (superadmins).
        ctl.load().then(function (ok) { if (ok) card.style.display = ''; }).catch(function () { /* not a superadmin */ });
    }

    var api = { mount: mount, questionText: questionText, CONFIRM_DELAY_MS: CONFIRM_DELAY_MS };
    if (typeof window !== 'undefined') window.ProxyTrustAdmin = api;
    if (typeof document !== 'undefined' && document.getElementById) {
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
        else bind();
    }
})();

/* Admin > System > Network: the reference lookup for block and rate-limit pages.

   An administrator pastes the ID a blocked or rate-limited person read out; GET
   /api/admin/blocks/ref/{id} answers with the stored event. Everything that comes from the server
   (address, reason, names) goes into the page with textContent. Handlers use addEventListener. The
   unblock button calls the existing DELETE /api/admin/blocked-ips/{ip}?ref=<id>, so that route's checks
   and its audit entry apply. */
(function (root) {
    'use strict';

    function create(doc, api) {
        var input = doc.getElementById('block-ref-input');
        var go = doc.getElementById('block-ref-go');
        var out = doc.getElementById('block-ref-result');
        if (!input || !go || !out) return null;

        function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
        function line(label, value) {
            var row = doc.createElement('div');
            var k = doc.createElement('strong');
            k.textContent = label + ': ';
            var v = doc.createElement('span');
            v.textContent = value === null || value === undefined || value === '' ? '-' : String(value);
            row.appendChild(k);
            row.appendChild(v);
            out.appendChild(row);
        }
        function message(text) {
            clear(out);
            var p = doc.createElement('div');
            p.textContent = text;
            out.appendChild(p);
        }
        function describe(d) {
            clear(out);
            line('Reference', d.ref);
            line('Event', d.kind === 'block' ? 'IP block' : (d.kind === 'limit' ? 'Rate limit' : 'Many sources (rate limit overflow)'));
            if (d.kind === 'limit' || d.kind === 'overflow') line('Limiter', d.limiter);
            if (d.kind === 'block') line('Block type', d.source);
            line('Address', d.address);
            line('Reason', d.reason);
            line('Account', d.account ? (d.account.username || ('#' + d.account.id)) : null);
            line('First seen', d.created_at);
            line('Last seen', d.last_seen);
            line('Requests counted', d.hits);
            if (d.kind === 'block') {
                line('Block active now', d.active ? 'yes' : 'no');
                if (d.block) {
                    line('Blocked by', d.block.blocked_by_username || 'system');
                    line('Blocked at', d.block.created_at);
                    line('Expires', d.block.expires_at || 'never');
                }
            }
            if (d.can_unblock) {
                var btn = doc.createElement('button');
                btn.setAttribute('type', 'button');
                btn.setAttribute('class', 'btn btn-secondary btn-sm');
                btn.setAttribute('id', 'block-ref-unblock');
                btn.textContent = 'Unblock ' + d.address;
                btn.addEventListener('click', function () { return unblock(d); });
                out.appendChild(btn);
            }
        }
        async function lookup() {
            var id = (input.value || '').trim();
            if (!id) { message('Enter a reference.'); return; }
            go.disabled = true;
            try {
                var res = await api.fetch('/api/admin/blocks/ref/' + encodeURIComponent(id));
                if (res.status === 404) message('No event found for that reference. It may have expired.');
                else if (res.status === 429) message('Too many lookups. Try again in a minute.');
                else if (!res.ok) message('The lookup failed (' + res.status + ').');
                else describe(await res.json());
            } catch (e) {
                message('The lookup failed.');
            } finally {
                go.disabled = false;
            }
        }
        async function unblock(d) {
            try {
                var res = await api.fetch('/api/admin/blocked-ips/' + encodeURIComponent(d.address) +
                                          '?ref=' + encodeURIComponent(d.ref), { method: 'DELETE' });
                if (res.ok) { api.toast('IP unblocked', 'success'); await lookup(); if (api.reload) api.reload(); }
                else {
                    var body = {};
                    try { body = await res.json(); } catch (e) { /* no body */ }
                    api.toast(body.error || 'Failed to unblock IP', 'error');
                }
            } catch (e) {
                api.toast('Failed to unblock IP', 'error');
            }
        }
        go.addEventListener('click', lookup);
        input.addEventListener('keydown', function (e) { if (e && e.key === 'Enter') lookup(); });
        return { lookup: lookup, describe: describe };
    }

    if (typeof module !== 'undefined' && module.exports) module.exports = { create: create };
    if (root && root.document) {
        var start = function () {
            create(root.document, {
                fetch: function (u, o) { return root.Portal.fetch(u, o); },
                toast: function (m, t) { root.Portal.toast(m, t); },
                reload: function () { if (typeof root.loadBlockedIps === 'function') root.loadBlockedIps(); }
            });
        };
        if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', start);
        else start();
    }
})(typeof window !== 'undefined' ? window : null);

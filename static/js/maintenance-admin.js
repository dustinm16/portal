/* Admin > Settings: the global maintenance flag and the announcements list.

   Everything that comes from the server (announcement text, messages, names) goes into the page
   with textContent or a text node; markup is only built from fixed strings here. Handlers are
   added with addEventListener. Times are shown and entered in the browser's own time zone and sent
   as UTC (ISO 8601 with a Z). */
(function () {
    'use strict';

    var FIELD = 'width:100%;background:rgba(0,0,0,0.3);border:1px solid var(--card-border);border-radius:6px;color:var(--text-primary);padding:0.5rem;box-sizing:border-box;';
    var MUTED = 'color:var(--text-muted);font-size:0.8rem;';

    function el(tag, props, children) {
        var e = document.createElement(tag);
        Object.keys(props || {}).forEach(function (k) {
            if (k === 'text') e.textContent = props[k];
            else if (k === 'style') e.setAttribute('style', props[k]);
            else if (k === 'class') e.className = props[k];
            else e.setAttribute(k, props[k]);
        });
        (children || []).forEach(function (c) { e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
        return e;
    }
    function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
    function label(text) { return el('label', { text: text, style: MUTED + 'display:block;margin-top:0.5rem;' }); }

    // "2026-11-23T20:00:00Z" <-> the value of a datetime-local input (local time)
    function toLocalInput(iso) {
        if (!iso) return '';
        var d = new Date(iso);
        if (isNaN(d.getTime())) return '';
        var p = function (n) { return String(n).padStart(2, '0'); };
        return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' + p(d.getMinutes());
    }
    function fromLocalInput(value) {
        if (!value) return null;
        var d = new Date(value);
        return isNaN(d.getTime()) ? null : d.toISOString().replace(/\.\d{3}Z$/, 'Z');
    }
    function shown(iso) {
        if (!iso) return 'open-ended';
        var d = new Date(iso);
        return isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
    }
    async function call(url, method, body) {
        var res = await Portal.fetch(url, {
            method: method || 'GET',
            headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
            body: body === undefined ? undefined : JSON.stringify(body)
        });
        var data = await res.json().catch(function () { return {}; });
        return { ok: res.ok, status: res.status, data: data };
    }
    function fail(r, fallback) { Portal.toast((r.data && r.data.error) || fallback, 'error'); }

    // ---- the global flag ----------------------------------------------------------------------------------
    function renderMaintenance(body, d) {
        clear(body);
        body.appendChild(el('p', { style: MUTED + 'margin:0 0 0.75rem 0;', text:
            'While it is on, members who are not administrators get a "Down for maintenance" page for /proxy, /browser and /search. ' +
            'Administrators pass through. Sign-in, the admin pages, the API, chat and every other page are never blocked. ' +
            'It can also be cleared from the server with: server.py maintenance-off' }));
        var state = d.active ? 'ON' + (d.until ? ' until ' + shown(d.until) : ' (open-ended)')
            : (d.set ? 'Off (the end time has passed)' : 'Off');
        body.appendChild(el('p', { style: 'margin:0 0 0.5rem 0;font-weight:600;', text: 'Status: ' + state }));
        if (d.set && d.set_by) body.appendChild(el('p', { style: MUTED + 'margin:0 0 0.5rem 0;', text: 'Set by ' + d.set_by + (d.set_at ? ' at ' + shown(d.set_at) : '') }));
        body.appendChild(label('Message shown to members (up to ' + (d.message_max || 200) + ' characters)'));
        var msg = el('input', { type: 'text', id: 'maint-message', maxlength: String(d.message_max || 200), style: FIELD });
        msg.value = d.message || '';
        body.appendChild(msg);
        body.appendChild(label('Ends at (your time zone; leave empty for open-ended)'));
        var until = el('input', { type: 'datetime-local', id: 'maint-until', style: FIELD });
        until.value = toLocalInput(d.until);
        body.appendChild(until);
        var row = el('div', { style: 'margin:0.75rem 0;display:flex;gap:0.5rem;flex-wrap:wrap;' });
        var on = el('button', { type: 'button', class: 'btn btn-primary', text: d.active ? 'Update' : 'Turn on' });
        on.addEventListener('click', function () {
            saveMaintenance(body, { active: true, message: msg.value, until: fromLocalInput(until.value) });
        });
        row.appendChild(on);
        if (d.set) {
            var off = el('button', { type: 'button', class: 'btn', text: 'Turn off' });
            off.addEventListener('click', function () { saveMaintenance(body, { active: false }); });
            row.appendChild(off);
        }
        body.appendChild(row);
    }
    async function saveMaintenance(body, payload) {
        try {
            var r = await call('/api/admin/maintenance', 'PUT', payload);
            if (!r.ok) { fail(r, 'Could not save'); return; }
            Portal.toast(payload.active ? 'Maintenance is on' : 'Maintenance is off', 'success');
            renderMaintenance(body, r.data);
        } catch (e) { Portal.toast('Could not save', 'error'); }
    }
    async function loadMaintenance() {
        var body = document.getElementById('maintenance-body');
        if (!body) return;
        try {
            var r = await call('/api/admin/maintenance');
            if (!r.ok) { body.textContent = 'Unavailable'; return; }
            renderMaintenance(body, r.data);
        } catch (e) { body.textContent = 'Unavailable'; }
    }

    // ---- announcements ---------------------------------------------------------------------------------------
    var levels = ['info', 'warning', 'outage'];
    var bodyMax = 1000;

    function form(body, current) {
        var box = el('div', { style: 'border:1px solid var(--card-border);border-radius:8px;padding:0.75rem;margin:0.75rem 0;' });
        box.appendChild(el('strong', { text: current ? 'Edit announcement' : 'New announcement' }));
        box.appendChild(label('Level'));
        var level = el('select', { style: FIELD });
        levels.forEach(function (l) { level.appendChild(el('option', { value: l, text: l })); });
        level.value = current ? current.level : 'info';
        box.appendChild(level);
        box.appendChild(label('Text (up to ' + bodyMax + ' characters; **bold**, *italic*, `code`, [label](https://link), line breaks)'));
        var text = el('textarea', { rows: '3', maxlength: String(bodyMax), style: FIELD });
        text.value = current ? current.body : '';
        box.appendChild(text);
        box.appendChild(label('Starts at (your time zone; empty = now)'));
        var starts = el('input', { type: 'datetime-local', style: FIELD });
        starts.value = current ? toLocalInput(current.starts_at) : '';
        box.appendChild(starts);
        box.appendChild(label('Ends at (empty = until ended by hand)'));
        var ends = el('input', { type: 'datetime-local', style: FIELD });
        ends.value = current ? toLocalInput(current.ends_at) : '';
        box.appendChild(ends);
        var startsShown = starts.value, endsShown = ends.value;
        var pre = el('input', { type: 'checkbox' });
        pre.checked = !!(current && current.show_before_signin);
        box.appendChild(el('label', { style: 'display:flex;align-items:center;gap:0.5rem;margin-top:0.75rem;' },
            [pre, 'Show before sign-in (visitors on the login page can read it)']));
        var row = el('div', { style: 'margin-top:0.75rem;display:flex;gap:0.5rem;' });
        var save = el('button', { type: 'button', class: 'btn btn-primary', text: current ? 'Save' : 'Publish' });
        save.addEventListener('click', async function () {
            var payload = { level: level.value, body: text.value, show_before_signin: pre.checked };
            // The times go in a minute-resolution input. An edit sends one only when the administrator
            // changed it: the stored time has seconds (and an ended announcement's end is in the past),
            // so sending the rounded value back would change it, or be refused as "in the past".
            if (!current || starts.value !== startsShown) payload.starts_at = fromLocalInput(starts.value);
            if (!current || ends.value !== endsShown) payload.ends_at = fromLocalInput(ends.value);
            try {
                var r = current ? await call('/api/admin/announcements/' + current.id, 'PUT', payload)
                                : await call('/api/admin/announcements', 'POST', payload);
                if (!r.ok) { fail(r, 'Could not save'); return; }
                Portal.toast('Saved', 'success');
                loadAnnouncements();
            } catch (e) { Portal.toast('Could not save', 'error'); }
        });
        var cancel = el('button', { type: 'button', class: 'btn', text: 'Cancel' });
        cancel.addEventListener('click', loadAnnouncements);
        row.appendChild(save);
        row.appendChild(cancel);
        box.appendChild(row);
        return box;
    }

    function renderAnnouncements(body, data) {
        clear(body);
        levels = data.levels || levels;
        bodyMax = data.body_max || bodyMax;
        body.appendChild(el('p', { style: MUTED + 'margin:0 0 0.75rem 0;', text:
            'A banner at the top of every page for signed-in members until they dismiss it or it ends. Editing the text shows it again to ' +
            'members who dismissed it. The text is never shown to visitors who are not signed in unless "Show before sign-in" is ticked.' }));
        var add = el('button', { type: 'button', class: 'btn btn-primary', text: 'New announcement' });
        add.addEventListener('click', function () {
            var existing = document.getElementById('announce-form-slot');
            clear(existing);
            existing.appendChild(form(body, null));
        });
        body.appendChild(add);
        body.appendChild(el('div', { id: 'announce-form-slot' }));
        var list = data.announcements || [];
        if (!list.length) { body.appendChild(el('p', { style: MUTED, text: 'No announcements.' })); return; }
        list.forEach(function (a) {
            var item = el('div', { style: 'border-top:1px solid var(--card-border);padding:0.6rem 0;' });
            item.appendChild(el('div', { style: 'font-weight:600;', text: a.level + ' - ' + a.status + (a.show_before_signin ? ' - shown before sign-in' : '') }));
            item.appendChild(el('div', { style: 'white-space:pre-wrap;overflow-wrap:anywhere;margin:0.25rem 0;', text: a.body }));
            item.appendChild(el('div', { style: MUTED, text: 'From ' + (a.starts_at ? shown(a.starts_at) : 'creation') + ' to ' + (a.ends_at ? shown(a.ends_at) : 'until ended') }));
            var row = el('div', { style: 'margin-top:0.4rem;display:flex;gap:0.5rem;flex-wrap:wrap;' });
            var edit = el('button', { type: 'button', class: 'btn', text: 'Edit' });
            edit.addEventListener('click', function () {
                var slot = document.getElementById('announce-form-slot');
                clear(slot);
                slot.appendChild(form(body, a));
                slot.scrollIntoView();
            });
            row.appendChild(edit);
            if (a.status !== 'ended') {
                var end = el('button', { type: 'button', class: 'btn', text: 'End now' });
                end.addEventListener('click', async function () {
                    var r = await call('/api/admin/announcements/' + a.id + '/end', 'POST');
                    if (!r.ok) { fail(r, 'Could not end it'); return; }
                    loadAnnouncements();
                });
                row.appendChild(end);
            }
            var del = el('button', { type: 'button', class: 'btn btn-danger', text: 'Delete' });
            del.addEventListener('click', async function () {
                if (!window.confirm('Delete this announcement?')) return;
                var r = await call('/api/admin/announcements/' + a.id, 'DELETE');
                if (!r.ok) { fail(r, 'Could not delete it'); return; }
                loadAnnouncements();
            });
            row.appendChild(del);
            item.appendChild(row);
            body.appendChild(item);
        });
    }
    async function loadAnnouncements() {
        var body = document.getElementById('announcements-body');
        if (!body) return;
        try {
            var r = await call('/api/admin/announcements');
            if (!r.ok) { body.textContent = 'Unavailable'; return; }
            renderAnnouncements(body, r.data);
        } catch (e) { body.textContent = 'Unavailable'; }
    }

    // ---- connections in maintenance: the way out when nobody can clear them any more ---------------------------
    function renderConnections(box, data) {
        clear(box);
        box.appendChild(el('strong', { text: 'Connections in maintenance' }));
        box.appendChild(el('p', { style: MUTED + 'margin:0.25rem 0 0.5rem 0;', text:
            'Only an administrator can put a connection in maintenance, and only one they own (a member\'s personal connections are the member\'s own). ' +
            'Any administrator can clear it here on any connection, for example one whose owner is no longer an administrator. Each clearing is audited.' }));
        var list = data.connections || [];
        if (!list.length) { box.appendChild(el('p', { style: MUTED, text: 'No connection is in maintenance.' })); return; }
        list.forEach(function (c) {
            var item = el('div', { style: 'border-top:1px solid var(--card-border);padding:0.5rem 0;display:flex;gap:0.75rem;align-items:center;flex-wrap:wrap;' });
            var info = el('div', { style: 'flex:1;min-width:12rem;overflow-wrap:anywhere;' });
            info.appendChild(el('div', { style: 'font-weight:600;', text: c.name + ' (owner: ' + c.owner + (c.owner_is_admin ? '' : ', not an administrator now') + ')' }));
            info.appendChild(el('div', { style: MUTED, text: (c.maintenance_active ? 'In maintenance until ' + shown(c.maintenance_until) : 'Flag set, end time has passed') +
                (c.maintenance_message ? ' - ' + c.maintenance_message : '') }));
            var b = el('button', { type: 'button', class: 'btn btn-sm', text: 'Clear maintenance' });
            b.addEventListener('click', async function () {
                try {
                    var r = await call('/api/admin/connections/' + encodeURIComponent(c.id) + '/maintenance/clear', 'POST', {});
                    if (!r.ok) { fail(r, 'Could not clear'); return; }
                    Portal.toast('Maintenance cleared', 'success');
                    loadConnections();
                } catch (e) { Portal.toast('Could not clear', 'error'); }
            });
            item.appendChild(info);
            item.appendChild(b);
            box.appendChild(item);
        });
    }
    async function loadConnections() {
        var box = document.getElementById('maintenance-conns');
        if (!box) return;
        try {
            var r = await call('/api/admin/connections/maintenance');
            if (!r.ok) { box.textContent = 'Unavailable'; return; }
            renderConnections(box, r.data);
        } catch (e) { box.textContent = 'Unavailable'; }
    }

    var api = { toLocalInput: toLocalInput, fromLocalInput: fromLocalInput, renderMaintenance: renderMaintenance,
                renderAnnouncements: renderAnnouncements, loadMaintenance: loadMaintenance, loadAnnouncements: loadAnnouncements,
                renderConnections: renderConnections, loadConnections: loadConnections, form: form };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (typeof window !== 'undefined') {
        window.MaintenanceAdmin = api;
        document.addEventListener('DOMContentLoaded', function () { loadMaintenance(); loadConnections(); loadAnnouncements(); });
    }
})();

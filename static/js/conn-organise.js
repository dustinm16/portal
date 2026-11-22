/**
 * Dashboard organising for My Connections: a filter box, personal folders and tags, a
 * "Recently used" row, a pin and an open mode per card. The filing is the caller's own
 * (connection_user_prefs on the server); the list API returns it as `prefs` on each item.
 *
 * Everything that comes from the server is put on the page with textContent or as an
 * attribute value, never as markup, and there are no inline handlers: every control is a
 * real button, link or field so the page works with a keyboard only.
 *
 * The pure part (matching, grouping, recents, tag parsing) has no DOM and is also run under
 * Node by tests/conn_organise_harness.js.
 */
(function (root) {
    'use strict';

    var RECENT_COUNT = 5;
    var UNFILED = '';
    var OPEN_MODES = [
        ['default', 'Default'],
        ['same', 'Same tab'],
        ['new', 'New tab'],
        ['embedded', 'Embedded browser']
    ];
    // Types that connectTo() hands to the portal's own HTTP proxy or embedded browser. Mirrors
    // the dedicated and TCP-only lists in user-connections.js: everything else is an HTTP type.
    var NOT_EMBEDDABLE = {
        sftp: 1, ssh: 1, terminal: 1, vnc: 1, rdp: 1, spice: 1, proxmox: 1, github: 1, mediamtx: 1, stream: 1,
        database: 1, redis: 1, mongodb: 1, postgresql: 1, mariadb: 1, telnet: 1, minecraft_rcon: 1,
        tcp_tunnel: 1, secure_tunnel: 1, vpn_tunnel: 1, custom: 1
    };

    function prefsOf(conn) {
        var p = (conn && conn.prefs) || {};
        return {
            folder: typeof p.folder === 'string' ? p.folder : '',
            tags: Array.isArray(p.tags) ? p.tags : [],
            open_mode: p.open_mode || 'default',
            pinned: !!p.pinned,
            last_opened_at: p.last_opened_at || null
        };
    }

    function canEmbed(conn) {
        return !NOT_EMBEDDABLE[conn && conn.type];
    }

    /** Words typed in the filter box (all must match) */
    function queryWords(text) {
        return String(text || '').toLowerCase().split(/\s+/).filter(Boolean);
    }

    /**
     * True when every word is in the item's name, type, folder, tags or host. The host is only
     * searched when the item JSON carries one: what the caller is not shown cannot be matched.
     */
    function matches(conn, words, tagSet) {
        var p = prefsOf(conn);
        if (tagSet && tagSet.length) {
            for (var i = 0; i < tagSet.length; i++) {
                if (p.tags.indexOf(tagSet[i]) < 0) return false;
            }
        }
        if (!words || !words.length) return true;
        var hay = [conn.name, conn.type, p.folder, p.tags.join(' '), conn.host].filter(Boolean).join('\n').toLowerCase();
        for (var j = 0; j < words.length; j++) {
            if (hay.indexOf(words[j]) < 0) return false;
        }
        return true;
    }

    function byName(a, b) {
        return String(a.name || '').toLowerCase().localeCompare(String(b.name || '').toLowerCase());
    }

    /** Pinned first, then by name */
    function sortItems(items) {
        return items.slice().sort(function (a, b) {
            var pa = prefsOf(a).pinned ? 0 : 1, pb = prefsOf(b).pinned ? 0 : 1;
            return pa - pb || byName(a, b);
        });
    }

    /** [{folder, items}] with named folders by name and the unfiled items last */
    function groupByFolder(conns) {
        var map = {};
        conns.forEach(function (c) {
            var f = prefsOf(c).folder;
            (map[f] = map[f] || []).push(c);
        });
        var names = Object.keys(map).filter(function (f) { return f !== UNFILED; });
        names.sort(function (a, b) { return a.toLowerCase().localeCompare(b.toLowerCase()); });
        if (map[UNFILED]) names.push(UNFILED);
        return names.map(function (f) { return { folder: f, items: sortItems(map[f]) }; });
    }

    /** The items opened most recently, newest first (at most `n`) */
    function recentItems(conns, n) {
        return conns.filter(function (c) { return prefsOf(c).last_opened_at; })
            .sort(function (a, b) {
                return String(prefsOf(b).last_opened_at).localeCompare(String(prefsOf(a).last_opened_at)) || byName(a, b);
            })
            .slice(0, n || RECENT_COUNT);
    }

    /** Every tag in use with how many items carry it, most used first */
    function tagCounts(conns) {
        var counts = {};
        conns.forEach(function (c) { prefsOf(c).tags.forEach(function (t) { counts[t] = (counts[t] || 0) + 1; }); });
        return Object.keys(counts).map(function (t) { return { tag: t, count: counts[t] }; })
            .sort(function (a, b) { return b.count - a.count || a.tag.localeCompare(b.tag); });
    }

    /** "a, b  c" into ["a", "b", "c"]: commas and spaces separate, empty pieces are dropped */
    function parseTags(text) {
        return String(text || '').split(/[,\s]+/).filter(Boolean);
    }

    /** What the match order is: the visible items in the order the folders show them */
    function orderedMatches(conns, words, tagSet) {
        var out = [];
        groupByFolder(conns.filter(function (c) { return matches(c, words, tagSet); }))
            .forEach(function (g) { g.items.forEach(function (c) { out.push(c); }); });
        return out;
    }

    /** Is this keydown the "/" shortcut? Not inside a field, not with a modifier. */
    function isSlashShortcut(e) {
        if (!e || e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return false;
        var t = e.target || {};
        var tag = String(t.tagName || '').toUpperCase();
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || t.isContentEditable) return false;
        return true;
    }

    var core = {
        prefsOf: prefsOf, canEmbed: canEmbed, queryWords: queryWords, matches: matches, sortItems: sortItems,
        groupByFolder: groupByFolder, recentItems: recentItems, tagCounts: tagCounts, parseTags: parseTags,
        orderedMatches: orderedMatches, isSlashShortcut: isSlashShortcut, OPEN_MODES: OPEN_MODES
    };

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = core;
    }
    if (typeof document === 'undefined') return;

    // ------------------------------------------------------------------ page part

    var state = { conns: [], words: [], tags: [], userKey: 'anon', dialogFor: null, opener: null };

    function $(id) { return document.getElementById(id); }

    function el(tag, cls, text) {
        var n = document.createElement(tag);
        if (cls) n.className = cls;
        if (text !== undefined && text !== null) n.textContent = text;
        return n;
    }

    function button(label, cls, title) {
        var b = el('button', cls || 'btn btn-secondary btn-sm', label);
        b.type = 'button';
        if (title) { b.title = title; b.setAttribute('aria-label', title); }
        return b;
    }

    function iconButton(svg, cls, title) {
        var b = el('button', cls || 'btn btn-secondary btn-sm');
        b.type = 'button';
        b.innerHTML = svg;  // static markup from this file, no server text
        b.title = title;
        b.setAttribute('aria-label', title);
        return b;
    }

    var SVG_PIN = '<svg xmlns="http://www.w3.org/2000/svg" fill="FILL" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z" /></svg>';
    var SVG_SHARE = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" /></svg>';
    var SVG_EDIT = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg>';
    var SVG_DELETE = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>';
    var SVG_TAG = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M3 3h8l10 10a2 2 0 010 2.828l-5.172 5.172a2 2 0 01-2.828 0L3 11V3z" /></svg>';

    // ---- collapsed folders, kept in this browser

    function storeKey() { return 'portal.dash.folders.' + state.userKey; }

    function collapsedSet() {
        try {
            var v = JSON.parse(localStorage.getItem(storeKey()) || '[]');
            return Array.isArray(v) ? v.filter(function (x) { return typeof x === 'string'; }) : [];
        } catch (e) { return []; }
    }

    function setCollapsed(folder, collapsed) {
        var list = collapsedSet().filter(function (f) { return f !== folder; });
        if (collapsed) list.push(folder);
        try { localStorage.setItem(storeKey(), JSON.stringify(list.slice(0, 200))); } catch (e) { /* storage full or blocked */ }
    }

    // ---- saving

    async function savePrefs(conn, fields) {
        try {
            var res = await Portal.api('/api/connections/' + encodeURIComponent(conn.id) + '/prefs', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(fields)
            });
            conn.prefs = res.prefs;
            render();
            return true;
        } catch (e) {
            Portal.toast(e.message || 'Could not save', 'error');
            render();
            return false;
        }
    }

    function openConn(conn) {
        if (typeof connectTo !== 'function') return;
        var p = prefsOf(conn);
        var mode = p.open_mode === 'embedded' && !canEmbed(conn) ? 'default' : p.open_mode;
        connectTo(conn.id, mode);
        // the server records the open; show it in "Recently used" at once
        conn.prefs = Object.assign({}, conn.prefs || {}, { last_opened_at: new Date().toISOString() });
        render();
    }

    // ---- cards

    function buildCard(conn, inRecent) {
        var p = prefsOf(conn);
        var card = el('div', 'connection-card' + (p.pinned ? ' connection-card-pinned' : ''));
        card.setAttribute('data-conn-id', conn.id);

        var head = el('div', 'connection-card-header');
        var icon = el('div', 'connection-icon');
        if (typeof getConnectionIcon === 'function') icon.innerHTML = getConnectionIcon(conn.icon || conn.type);  // static svg
        var info = el('div', 'connection-info');
        var h4 = el('h4');
        h4.appendChild(document.createTextNode(conn.name + ' '));
        var type = String(conn.type || 'unknown');
        var badge = el('span', 'conn-type-badge', type.toUpperCase());
        badge.className += ' conn-type-' + type.replace(/[^A-Za-z0-9_-]/g, '');
        h4.appendChild(badge);
        if (root.ConnHealth) {  // status dot (connection health checks); none while the feature is off
            var hdot = root.ConnHealth.dot(conn.id);
            if (hdot) h4.appendChild(hdot);
        }
        var host = el('span', 'connection-host', (conn.host || '') + (conn.port ? ':' + conn.port : ''));
        info.appendChild(h4);
        info.appendChild(host);
        head.appendChild(icon);
        head.appendChild(info);
        card.appendChild(head);

        var meta = el('div', 'conn-card-meta');
        if (p.folder && !inRecent) meta.appendChild(el('span', 'conn-folder-label', p.folder));
        p.tags.forEach(function (t) {
            var chip = button('#' + t, 'conn-tag conn-tag-small', 'Filter by tag ' + t);
            chip.setAttribute('data-tag', t);
            chip.setAttribute('aria-pressed', state.tags.indexOf(t) >= 0 ? 'true' : 'false');
            meta.appendChild(chip);
        });
        if (meta.childNodes.length) card.appendChild(meta);

        var details = el('div', 'connection-details');
        var line;
        if (conn.shared) {
            var left = typeof formatGrantRemaining === 'function' ? formatGrantRemaining(conn.share_expires_in) : '';
            line = 'Shared by ' + (conn.owner_username || '?') + (left ? ' · ' + left : '');
        } else if (conn.last_used_at && typeof Portal.formatRelativeTime === 'function') {
            line = 'Used ' + Portal.formatRelativeTime(conn.last_used_at);
        } else {
            line = 'Never used';
        }
        details.appendChild(el('span', 'connection-time', line));
        card.appendChild(details);

        var actions = el('div', 'connection-actions');
        var connect = button('Connect', 'btn btn-primary btn-sm connection-connect-btn');
        connect.setAttribute('data-act', 'connect');
        actions.appendChild(connect);

        var pin = iconButton(SVG_PIN.replace('FILL', p.pinned ? 'currentColor' : 'none'),
            'btn btn-sm ' + (p.pinned ? 'btn-primary' : 'btn-secondary'), p.pinned ? 'Unpin' : 'Pin');
        pin.setAttribute('data-act', 'pin');
        pin.setAttribute('aria-pressed', p.pinned ? 'true' : 'false');
        actions.appendChild(pin);

        var org = iconButton(SVG_TAG, 'btn btn-secondary btn-sm', 'Folder and tags');
        org.setAttribute('data-act', 'organise');
        actions.appendChild(org);

        if (conn.shared) {
            var leave = button('Leave', 'btn btn-secondary btn-sm', 'Remove my access');
            leave.textContent = 'Leave';
            leave.setAttribute('data-act', 'leave');
            actions.appendChild(leave);
        } else {
            var share = iconButton(SVG_SHARE, 'btn btn-secondary btn-sm', 'Share');
            share.setAttribute('data-act', 'share');
            var edit = iconButton(SVG_EDIT, 'btn btn-secondary btn-sm', 'Edit');
            edit.setAttribute('data-act', 'edit');
            var del = iconButton(SVG_DELETE, 'btn btn-danger btn-sm', 'Delete');
            del.setAttribute('data-act', 'delete');
            actions.appendChild(share);
            actions.appendChild(edit);
            actions.appendChild(del);
        }
        card.appendChild(actions);

        var modeRow = el('label', 'conn-open-mode');
        modeRow.appendChild(el('span', 'conn-open-mode-label', 'Open in'));
        var sel = el('select', 'conn-open-mode-select');
        sel.setAttribute('data-act', 'open-mode');
        OPEN_MODES.forEach(function (m) {
            if (m[0] === 'embedded' && !canEmbed(conn)) return;
            var o = el('option', '', m[1]);
            o.value = m[0];
            if (m[0] === p.open_mode) o.selected = true;
            sel.appendChild(o);
        });
        modeRow.appendChild(sel);
        card.appendChild(modeRow);
        return card;
    }

    function findConn(card) {
        var id = card && card.getAttribute('data-conn-id');
        for (var i = 0; i < state.conns.length; i++) if (state.conns[i].id === id) return state.conns[i];
        return null;
    }

    function onGridClick(e) {
        var target = e.target.closest ? e.target.closest('button') : null;
        if (!target) return;
        var card = target.closest('.connection-card');
        var conn = findConn(card);
        if (!conn) return;
        var tag = target.getAttribute('data-tag');
        if (tag) { toggleTag(tag); return; }
        var act = target.getAttribute('data-act');
        if (act === 'connect') openConn(conn);
        else if (act === 'pin') savePrefs(conn, { pinned: !prefsOf(conn).pinned });
        else if (act === 'organise') openDialog(conn, target);
        else if (act === 'leave' && typeof leaveSharedConnection === 'function') leaveSharedConnection(conn.id);
        else if (act === 'share' && typeof showShareConnectionModal === 'function') showShareConnectionModal(conn.id, conn.name);
        else if (act === 'edit' && typeof editConnection === 'function') editConnection(conn.id);
        else if (act === 'delete' && typeof confirmDeleteConnection === 'function') confirmDeleteConnection(conn.id, conn.name);
    }

    function onGridChange(e) {
        var t = e.target;
        if (!t || t.getAttribute('data-act') !== 'open-mode') return;
        var conn = findConn(t.closest('.connection-card'));
        if (conn) savePrefs(conn, { open_mode: t.value });
    }

    // ---- sections

    function toggleTag(tag) {
        var i = state.tags.indexOf(tag);
        if (i >= 0) state.tags.splice(i, 1); else state.tags.push(tag);
        render();
    }

    function renderChips() {
        var box = $('conn-tag-chips');
        if (!box) return;
        box.textContent = '';
        var counts = tagCounts(state.conns);
        state.tags = state.tags.filter(function (t) { return counts.some(function (c) { return c.tag === t; }); });
        counts.forEach(function (c) {
            var b = button('#' + c.tag + ' ' + c.count, 'conn-tag', 'Filter by tag ' + c.tag);
            b.setAttribute('data-tag', c.tag);
            b.setAttribute('aria-pressed', state.tags.indexOf(c.tag) >= 0 ? 'true' : 'false');
            box.appendChild(b);
        });
        box.hidden = counts.length === 0;
    }

    function renderRecent() {
        var wrap = $('conn-recent'), grid = $('conn-recent-grid');
        if (!wrap || !grid) return;
        grid.textContent = '';
        var items = recentItems(state.conns, RECENT_COUNT);
        wrap.hidden = items.length === 0;
        items.forEach(function (c) { grid.appendChild(buildCard(c, true)); });
    }

    function renderFolders() {
        var root = $('inline-connections-grid');
        if (!root) return;
        root.textContent = '';
        var filtering = state.words.length > 0 || state.tags.length > 0;
        var shown = state.conns.filter(function (c) { return matches(c, state.words, state.tags); });
        var groups = groupByFolder(shown);
        var named = groups.filter(function (g) { return g.folder !== UNFILED; }).length;
        var collapsed = collapsedSet();
        groups.forEach(function (g) {
            var section = el('section', 'conn-folder');
            // a lone unfiled group needs no heading
            if (named > 0 || g.folder !== UNFILED) {
                var isCollapsed = !filtering && collapsed.indexOf(g.folder) >= 0;
                var head = button('', 'conn-folder-head');
                head.setAttribute('data-folder', g.folder);
                head.setAttribute('aria-expanded', isCollapsed ? 'false' : 'true');
                head.appendChild(el('span', 'conn-folder-caret', isCollapsed ? '▶' : '▼'));
                head.appendChild(el('span', 'conn-folder-name', g.folder === UNFILED ? 'Unfiled' : g.folder));
                head.appendChild(el('span', 'conn-folder-count', String(g.items.length)));
                section.appendChild(head);
                if (isCollapsed) { root.appendChild(section); return; }
            }
            var grid = el('div', 'connections-grid');
            g.items.forEach(function (c) { grid.appendChild(buildCard(c, false)); });
            section.appendChild(grid);
            root.appendChild(section);
        });
        var none = $('conn-filter-none');
        if (none) none.hidden = !(state.conns.length && !shown.length);
    }

    function onFolderClick(e) {
        var head = e.target.closest ? e.target.closest('.conn-folder-head') : null;
        if (!head) return;
        var folder = head.getAttribute('data-folder');
        setCollapsed(folder, collapsedSet().indexOf(folder) < 0);
        render();
        var again = document.querySelector('.conn-folder-head[data-folder="' + (window.CSS && CSS.escape ? CSS.escape(folder) : folder) + '"]');
        if (again) again.focus();
    }

    function render() {
        renderChips();
        renderRecent();
        renderFolders();
        var clear = $('conn-filter-clear');
        if (clear) clear.hidden = !(state.words.length || state.tags.length);
    }

    // ---- dialog

    function openDialog(conn, opener) {
        var modal = $('conn-organise-modal');
        if (!modal) return;
        state.dialogFor = conn;
        state.opener = opener || null;
        var p = prefsOf(conn);
        $('conn-organise-name').textContent = conn.name;
        $('conn-organise-folder').value = p.folder;
        $('conn-organise-tags').value = p.tags.join(', ');
        var list = $('conn-organise-folders');
        list.textContent = '';
        var seen = {};
        state.conns.forEach(function (c) {
            var f = prefsOf(c).folder;
            if (f && !seen[f]) { seen[f] = 1; var o = document.createElement('option'); o.value = f; list.appendChild(o); }
        });
        $('conn-organise-error').textContent = '';
        modal.style.display = 'flex';
        $('conn-organise-folder').focus();
    }

    function closeDialog() {
        var modal = $('conn-organise-modal');
        if (modal) modal.style.display = 'none';
        var back = state.opener;
        state.dialogFor = null;
        state.opener = null;
        if (back && document.body.contains(back)) back.focus();
    }

    async function saveDialog(e) {
        if (e) e.preventDefault();
        var conn = state.dialogFor;
        if (!conn) return;
        var fields = { folder: $('conn-organise-folder').value, tags: parseTags($('conn-organise-tags').value) };
        try {
            var res = await Portal.api('/api/connections/' + encodeURIComponent(conn.id) + '/prefs', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(fields)
            });
            conn.prefs = res.prefs;
            closeDialog();
            render();
        } catch (err) {
            $('conn-organise-error').textContent = err.message || 'Could not save';
        }
    }

    // ---- filter box

    function activeTabName() {
        var t = document.querySelector('.tab-content.active');
        return t ? t.id : '';
    }

    function applyServiceFilter() {
        var input = $('svc-filter');
        var words = queryWords(input ? input.value : '');
        var first = null;
        document.querySelectorAll('#services-grid .service-card').forEach(function (card) {
            // the name and the plugin only: the button labels and the status text would make
            // "log" or "stop" match every card
            var nameEl = card.querySelector('.service-name'), plugEl = card.querySelector('.service-plugin');
            var text = ((nameEl ? nameEl.textContent : '') + ' ' + (plugEl ? plugEl.textContent : '')).toLowerCase();
            var ok = words.every(function (w) { return text.indexOf(w) >= 0; });
            card.classList.toggle('conn-hidden', !ok);
            if (ok && !first) first = card;
        });
        var clear = $('svc-filter-clear');
        if (clear) clear.hidden = !words.length;
        return first;
    }

    function wire() {
        var input = $('conn-filter');
        if (input) {
            input.addEventListener('input', function () { state.words = queryWords(input.value); render(); });
            input.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    var first = orderedMatches(state.conns, state.words, state.tags)[0];
                    if (first) openConn(first);
                } else if (e.key === 'Escape' && input.value) {
                    input.value = '';
                    state.words = [];
                    render();
                }
            });
        }
        var clear = $('conn-filter-clear');
        if (clear) clear.addEventListener('click', function () {
            if (input) input.value = '';
            state.words = []; state.tags = [];
            render();
            if (input) input.focus();
        });
        ['conn-tag-chips', 'inline-connections-grid', 'conn-recent-grid'].forEach(function (id) {
            var n = $(id);
            if (!n) return;
            n.addEventListener('click', id === 'conn-tag-chips'
                ? function (e) { var b = e.target.closest('button'); if (b && b.getAttribute('data-tag')) toggleTag(b.getAttribute('data-tag')); }
                : function (e) { onFolderClick(e); onGridClick(e); });
            n.addEventListener('change', onGridChange);
        });

        var sinput = $('svc-filter');
        if (sinput) {
            sinput.addEventListener('input', applyServiceFilter);
            sinput.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') { e.preventDefault(); var f = applyServiceFilter(); if (f) f.click(); }
                else if (e.key === 'Escape' && sinput.value) { sinput.value = ''; applyServiceFilter(); }
            });
        }
        var sclear = $('svc-filter-clear');
        if (sclear) sclear.addEventListener('click', function () { if (sinput) { sinput.value = ''; applyServiceFilter(); sinput.focus(); } });

        var form = $('conn-organise-form');
        if (form) form.addEventListener('submit', saveDialog);
        var cancel = $('conn-organise-cancel');
        if (cancel) cancel.addEventListener('click', closeDialog);
        var back = $('conn-organise-backdrop');
        if (back) back.addEventListener('click', closeDialog);
        var modal = $('conn-organise-modal');
        if (modal) modal.addEventListener('keydown', function (e) { if (e.key === 'Escape') { e.stopPropagation(); closeDialog(); } });

        document.addEventListener('keydown', function (e) {
            if (!isSlashShortcut(e)) return;
            var tab = activeTabName();
            var target = tab === 'tab-my-connections' ? $('conn-filter') : tab === 'tab-services' ? $('svc-filter') : null;
            if (!target) return;
            e.preventDefault();
            target.focus();
            target.select();
        });
    }

    root.ConnOrganiser = {
        /** Show the caller's connections (the list API's items, each with `prefs`) */
        show: function (conns, userKey) {
            state.conns = Array.isArray(conns) ? conns : [];
            state.userKey = String(userKey || 'anon');
            render();
        },
        applyServiceFilter: applyServiceFilter,
        core: core
    };

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
    else wire();
})(typeof window !== 'undefined' ? window : globalThis);

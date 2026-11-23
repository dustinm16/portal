/* Saved messages and remind-me-later for the chat page.
 *
 * The server keeps a reference only (see /api/saved); this file shows what it resolves live. The
 * member's own marker, the Save and Remind entries of the message menu, the Saved view and the
 * reminder dialog are all built here from text nodes (textContent, never innerHTML), so a message
 * text, a user name or a channel name cannot become markup. Nothing here sends a WebSocket frame:
 * what one member saved is known to that member's browser and to the server, to nobody else.
 *
 * The page hands in what it owns through ChatSaved.init(cfg):
 *   cfg.currentKind()          'channel' or 'dm' for the view on screen
 *   cfg.jumpToMessage(channelId, messageId)    the page's jump-to-message
 *   cfg.openDm(conversationId) open a direct-message conversation
 *   cfg.hideMenus()            close the context menus
 *   cfg.toast(text, type)      optional; falls back to Portal.toast
 *   cfg.api(method, path, body) optional; falls back to Portal.fetch. Resolves to {status, data}.
 * The time helpers are pure (a Date in, a Date or text out) and are tested under Node in two time
 * zones (tests/chat_saved_harness.js).
 */
(function (root) {
    'use strict';

    var MENU_SAVE_ID = 'saved-menu-item';
    var MENU_REMIND_ID = 'remind-menu-item';
    var OPEN_BUTTON_ID = 'saved-open-btn';
    var DEFAULT_HORIZON_DAYS = 366;
    var MARKS_REFRESH_MS = 60 * 1000;     /* returning to the tab refreshes the marks at most this often */
    var state = {
        cfg: null, doc: null, marks: new Map(), limits: null, menuMsg: null,
        panel: null, remind: null, opener: null, observer: null, items: new Map(), nextBefore: null,
        marksAt: 0, marksStale: false
    };

    /* ---------------------------------------------------------------- time (pure) */
    function pad2(n) { return (n < 10 ? '0' : '') + n; }

    /* A Date as the absolute UTC instant the server wants: 2026-11-24T08:00:00Z */
    function utcIso(date) {
        return date.getUTCFullYear() + '-' + pad2(date.getUTCMonth() + 1) + '-' + pad2(date.getUTCDate()) +
            'T' + pad2(date.getUTCHours()) + ':' + pad2(date.getUTCMinutes()) + ':' + pad2(date.getUTCSeconds()) + 'Z';
    }

    function atNineLocal(now, addDays) {
        return new Date(now.getFullYear(), now.getMonth(), now.getDate() + addDays, 9, 0, 0, 0);
    }

    /* The quick choices: in one hour, tomorrow 09:00 and next Monday 09:00 (local time of the member;
     * when today is Monday, the Monday a week away). */
    function remindChoices(now) {
        var untilMonday = ((1 - now.getDay() + 7) % 7) || 7;
        return [
            { key: 'hour', label: 'In 1 hour', when: new Date(now.getTime() + 3600 * 1000) },
            { key: 'tomorrow', label: 'Tomorrow 9:00', when: atNineLocal(now, 1) },
            { key: 'nextweek', label: 'Next week (Monday 9:00)', when: atNineLocal(now, untilMonday) }
        ];
    }

    /* The value of <input type="datetime-local"> ("2026-11-24T09:00") as a local Date; null for anything
     * that is not a real date (month 13, 30 February). */
    function parseLocalInput(value) {
        var m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::\d{2}(?:\.\d+)?)?$/.exec(String(value || ''));
        if (!m) return null;
        var y = +m[1], mo = +m[2], d = +m[3], h = +m[4], mi = +m[5];
        var date = new Date(y, mo - 1, d, h, mi, 0, 0);
        if (date.getFullYear() !== y || date.getMonth() !== mo - 1 || date.getDate() !== d ||
            date.getHours() !== h || date.getMinutes() !== mi) return null;
        return date;
    }

    /* Text for the member when the time cannot be used, else ''. */
    function whenProblem(date, now, horizonDays) {
        if (!date || Object.prototype.toString.call(date) !== '[object Date]' || isNaN(date.getTime())) return 'Choose a date and a time.';
        if (date.getTime() <= now.getTime()) return 'Choose a time in the future.';
        var days = horizonDays || DEFAULT_HORIZON_DAYS;
        if (date.getTime() > now.getTime() + days * 86400 * 1000) return 'Choose a time less than ' + days + ' days ahead.';
        return '';
    }

    function formatWhen(iso) {
        var d = new Date(iso);
        if (isNaN(d.getTime())) return '';
        try {
            return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
        } catch (e) {
            return d.toString();
        }
    }

    /* value for the picker's min attribute: now, local, to the minute */
    function localInputValue(date) {
        return date.getFullYear() + '-' + pad2(date.getMonth() + 1) + '-' + pad2(date.getDate()) +
            'T' + pad2(date.getHours()) + ':' + pad2(date.getMinutes());
    }

    /* ---------------------------------------------------------------- helpers */
    function doc() { return state.doc || root.document; }
    function now() { return (state.cfg && state.cfg.now) ? state.cfg.now() : new Date(); }
    function markKey(kind, id) { return kind + ':' + id; }

    function el(tag, text, cls, attrs) {
        var n = doc().createElement(tag);
        if (text) n.textContent = text;
        if (cls) n.className = cls;
        if (attrs) Object.keys(attrs).forEach(function (k) { n.setAttribute(k, attrs[k]); });
        return n;
    }

    function button(label, cls, onClick, extra) {
        var b = el('button', label, 'btn btn-sm ' + (cls || ''), Object.assign({ type: 'button' }, extra || {}));
        b.addEventListener('click', onClick);
        return b;
    }

    function toast(text, type) {
        var cfg = state.cfg || {};
        if (cfg.toast) cfg.toast(text, type);
        else if (root.Portal && root.Portal.toast) root.Portal.toast(text, type);
    }

    function api(method, path, body) {
        var cfg = state.cfg || {};
        if (cfg.api) return cfg.api(method, path, body);
        var opts = { method: method, headers: {} };
        if (body !== undefined) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        var f = (root.Portal && root.Portal.fetch) ? root.Portal.fetch.bind(root.Portal) : root.fetch.bind(root);
        return f(path, opts).then(function (r) {
            return r.json().catch(function () { return {}; }).then(function (data) { return { status: r.status, data: data }; });
        });
    }

    function errorText(res, fallback) {
        return (res && res.data && res.data.error) || fallback;
    }

    /* ---------------------------------------------------------------- the marker */
    /* A small visible button on every message, for a touch screen: the message menu (reply, react, copy,
     * Save, Remind and the rest) opens only on a right click or the menu key, and iOS Safari does not fire
     * a context menu on a long press. The style sheet shows it only where there is no hover or the pointer
     * is coarse; the click opens the same menu (see onMessagesClick). */
    function addActionsButton(row) {
        if (!row.querySelector || row.classList.contains('system')) return;
        if (!(parseInt(row.dataset.messageId, 10) > 0) || row.querySelector('.msg-actions-btn')) return;
        var b = el('button', '...', 'msg-actions-btn', {
            type: 'button', 'aria-label': 'Message actions', 'aria-haspopup': 'menu',
            title: 'Message actions: reply, react, copy, save, remind me'
        });
        (row.querySelector('.message-header') || row).appendChild(b);
    }

    function decorate(row) {
        if (!row || !row.dataset || !state.cfg) return;
        addActionsButton(row);
        var id = parseInt(row.dataset.messageId, 10);
        var saved = id > 0 && state.marks.has(markKey(state.cfg.currentKind(), id));
        var has = row.classList.contains('saved-message');
        if (saved && !has) {
            row.classList.add('saved-message');
            var header = row.querySelector ? row.querySelector('.message-header') : null;
            if (header && !header.querySelector('.saved-badge')) {
                /* before the actions button, which stays last in the header */
                header.insertBefore(el('span', 'Saved', 'saved-badge', { title: 'Saved by you; only you see this' }),
                                    header.querySelector('.msg-actions-btn'));
            }
        } else if (!saved && has) {
            row.classList.remove('saved-message');
            var badge = row.querySelector ? row.querySelector('.saved-badge') : null;
            if (badge && badge.remove) badge.remove();
        }
    }

    function decorateAll() {
        var c = doc().getElementById('chat-messages');
        if (!c || !c.querySelectorAll) return;
        Array.prototype.forEach.call(c.querySelectorAll('.message[data-message-id]'), decorate);
    }

    /* Always asks. The time is stamped when the request goes out, so a refused or failed answer (the route
     * has a rate limit) is not asked again at once either. */
    function loadMarks() {
        state.marksAt = now().getTime();
        state.marksStale = false;
        return api('GET', '/api/saved/marks').then(function (res) {
            if (res.status !== 200 || !res.data) return;
            state.marks = new Map();
            (res.data.marks || []).forEach(function (m) { state.marks.set(markKey(m.kind, m.message_id), m.id); });
            if (res.data.limits) state.limits = res.data.limits;
            decorateAll();
        }).catch(function () { /* the marker is a convenience */ });
    }

    /* Coming back to the tab: the marks are asked for at most once per MARKS_REFRESH_MS, unless the member
     * saved or removed something since (then the next return asks, so the marker follows the server). */
    function refreshMarks() {
        var t = now().getTime();
        if (!state.marksStale && state.marksAt && t >= state.marksAt && t - state.marksAt < MARKS_REFRESH_MS) {
            return Promise.resolve();
        }
        return loadMarks();
    }

    /* ---------------------------------------------------------------- save, remove, remind from a message */
    function prepareMenu(messageId) {
        var kind = state.cfg.currentKind();
        state.menuMsg = { id: parseInt(messageId, 10), kind: kind };
        var item = doc().getElementById(MENU_SAVE_ID);
        if (item) item.textContent = state.marks.has(markKey(kind, state.menuMsg.id)) ? 'Remove from Saved' : 'Save message';
    }

    function saveMessage(msg) {
        return api('POST', '/api/saved', { kind: msg.kind, message_id: msg.id }).then(function (res) {
            if (res.status === 200 || res.status === 201) {
                var s = res.data.saved;
                state.marks.set(markKey(msg.kind, msg.id), s.id);
                state.marksStale = true;
                decorateAll();
                return s;
            }
            toast(errorText(res, 'That message could not be saved.'), 'error');
            return null;
        }).catch(function () { toast('That message could not be saved.', 'error'); return null; });
    }

    function removeSaved(savedId) {
        return api('DELETE', '/api/saved/' + savedId).then(function (res) {
            if (res.status !== 200 && res.status !== 404) {
                toast(errorText(res, 'Could not remove it.'), 'error');
                return false;
            }
            state.marks.forEach(function (v, k) { if (v === savedId) state.marks.delete(k); });
            state.marksStale = true;
            decorateAll();
            return true;
        }).catch(function () { toast('Could not remove it.', 'error'); return false; });
    }

    function toggleCurrent() {
        var msg = state.menuMsg;
        if (state.cfg.hideMenus) state.cfg.hideMenus();
        if (!msg || !(msg.id > 0)) { toast('That message is not ready yet.', 'error'); return Promise.resolve(); }
        var existing = state.marks.get(markKey(msg.kind, msg.id));
        if (existing) {
            return removeSaved(existing).then(function (ok) { if (ok) toast('Removed from Saved', 'success'); });
        }
        return saveMessage(msg).then(function (s) { if (s) toast('Saved. Only you can see it.', 'success'); });
    }

    /* The marks carry no reminder time and there is no route for one entry, so the entry is read through the list:
     * the single entry at or below its id (ids are the list's cursor) is the entry itself, or another one when it is
     * gone. Null when it cannot be read (a limit, the network): the dialog then opens without its current time. */
    function readEntry(savedId) {
        return api('GET', '/api/saved?limit=1&before_id=' + (savedId + 1)).then(function (res) {
            var it = res.status === 200 && res.data && res.data.items && res.data.items[0];
            return it && it.id === savedId ? it : null;
        }).catch(function () { return null; });
    }

    function remindCurrent() {
        var msg = state.menuMsg;
        if (state.cfg.hideMenus) state.cfg.hideMenus();
        if (!msg || !(msg.id > 0)) { toast('That message is not ready yet.', 'error'); return Promise.resolve(); }
        var existing = state.marks.get(markKey(msg.kind, msg.id));
        if (existing) {
            return readEntry(existing).then(function (it) {
                openRemind(existing, it && it.remind_at && !it.reminded ? it.remind_at : null, null);
            });
        }
        /* it stays saved if the dialog is cancelled, so the member is told it was saved */
        return saveMessage(msg).then(function (s) {
            if (!s) return;
            toast('Saved. Only you can see it.', 'success');
            openRemind(s.id, null, null);
        });
    }

    /* ---------------------------------------------------------------- the reminder dialog */
    function closeRemind() {
        var r = state.remind;
        if (!r) return;
        state.remind = null;
        if (r.node.parentNode) r.node.parentNode.removeChild(r.node);
        if (r.opener && r.opener.focus) r.opener.focus();
    }

    function setReminder(savedId, when, onDone, errorEl) {
        var iso = when === null ? null : utcIso(when);
        return api('PUT', '/api/saved/' + savedId + '/remind', { remind_at: iso }).then(function (res) {
            if (res.status === 200) {
                toast(iso ? 'Reminder set for ' + formatWhen(res.data.remind_at) : 'Reminder cleared', 'success');
                if (onDone) onDone(res.data);
                closeRemind();
                return true;
            }
            var text = errorText(res, 'The reminder could not be set.');
            if (errorEl) errorEl.textContent = text; else toast(text, 'error');
            return false;
        }).catch(function () {
            if (errorEl) errorEl.textContent = 'The reminder could not be set.';
            return false;
        });
    }

    function openRemind(savedId, currentIso, onDone) {
        closeRemind();
        var horizon = state.limits && state.limits.reminder_horizon_days;
        var overlay = el('div', '', 'saved-overlay saved-overlay-remind');
        var dlg = el('div', '', 'saved-panel saved-remind', { role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'saved-remind-title' });
        var title = el('h2', 'Remind me', 'saved-title', { id: 'saved-remind-title', tabindex: '-1' });
        var err = el('p', '', 'saved-error', { role: 'alert' });
        var choices = el('div', '', 'saved-remind-choices');
        remindChoices(now()).forEach(function (c) {
            choices.appendChild(button(c.label, 'btn-secondary', function () {
                var problem = whenProblem(c.when, now(), horizon);
                if (problem) { err.textContent = problem; return; }
                setReminder(savedId, c.when, onDone, err);
            }, { 'data-choice': c.key }));
        });
        var label = el('label', 'Date and time', 'saved-label', { for: 'saved-remind-input' });
        var input = el('input', '', 'saved-input', { id: 'saved-remind-input', type: 'datetime-local' });
        input.setAttribute('min', localInputValue(now()));
        var set = button('Set reminder', 'btn-primary', function () {
            var when = parseLocalInput(input.value);
            var problem = whenProblem(when, now(), horizon);
            if (problem) { err.textContent = problem; return; }
            setReminder(savedId, when, onDone, err);
        }, { 'data-choice': 'custom' });
        var row = el('div', '', 'saved-remind-custom');
        row.append(label, input, set);
        var current = null;
        if (currentIso) {
            /* the reminder that is set now: its time is shown and offered in the picker, and it can be cleared */
            current = el('p', 'Current reminder: ' + formatWhen(currentIso), 'saved-meta saved-current');
            var cur = new Date(currentIso);
            if (!isNaN(cur.getTime())) input.value = localInputValue(cur);
        }
        var foot = el('div', '', 'saved-actions');
        if (currentIso) {
            foot.appendChild(button('Clear reminder', 'btn-secondary', function () { setReminder(savedId, null, onDone, err); }, { 'data-choice': 'clear' }));
        }
        foot.appendChild(button('Cancel', 'btn-secondary', closeRemind, { 'data-choice': 'cancel' }));
        if (current) dlg.append(title, current, choices, row, err, foot);
        else dlg.append(title, choices, row, err, foot);
        overlay.appendChild(dlg);
        overlay.addEventListener('click', function (e) { if (e.target === overlay) closeRemind(); });
        doc().body.appendChild(overlay);
        state.remind = { node: overlay, dlg: dlg, opener: doc().activeElement };
        if (title.focus) title.focus();
        return state.remind;
    }

    /* ---------------------------------------------------------------- the Saved view */
    function reminderText(item) {
        if (item.reminded && item.remind_at) return 'Reminder sent ' + formatWhen(item.remind_at);
        if (item.remind_at) return 'Reminder: ' + formatWhen(item.remind_at);
        return '';
    }

    function renderItem(item) {
        var li = el('div', '', 'saved-item', { role: 'listitem', 'data-saved-id': String(item.id) });
        var body = el('div', '', 'saved-item-body');
        var remindLine = el('div', reminderText(item), 'saved-meta saved-reminder');
        var actions = el('div', '', 'saved-actions');
        state.items.set(item.id, { item: item, remindLine: remindLine });
        if (item.available) {
            var where = item.kind === 'dm' ? 'a direct message' : '#' + (item.channel_name || '');
            var head = el('div', '', 'saved-meta');
            head.appendChild(el('strong', (item.message && item.message.username) || '', 'saved-author'));
            head.appendChild(el('span', ' in ' + where + (item.message && item.message.created_at ? ', ' + formatWhen(item.message.created_at) : '')));
            var text = el('div', String((item.message && item.message.text) || '').slice(0, 600), 'saved-text');
            body.append(head, text, el('div', 'Saved ' + formatWhen(item.saved_at), 'saved-meta'), remindLine);
            actions.appendChild(button('Jump to message', 'btn-primary', function () { jump(item); }, { 'data-action': 'jump' }));
            actions.appendChild(button('Remind me', 'btn-secondary', function () {
                openRemind(item.id, item.reminded ? null : item.remind_at, function (data) {
                    item.remind_at = data.remind_at;
                    item.reminded = !!data.reminded;
                    remindLine.textContent = reminderText(item);
                });
            }, { 'data-action': 'remind' }));
        } else {
            body.append(el('div', 'No longer available', 'saved-gone'),
                        el('div', 'Saved ' + formatWhen(item.saved_at), 'saved-meta'), remindLine);
        }
        actions.appendChild(button('Remove', 'btn-secondary', function () {
            removeSaved(item.id).then(function (ok) {
                if (!ok) return;
                state.items.delete(item.id);
                if (li.parentNode) li.parentNode.removeChild(li);
                if (state.panel && !state.panel.list.children.length) showEmpty();
            });
        }, { 'data-action': 'remove' }));
        li.append(body, actions);
        return li;
    }

    function jump(item) {
        var cfg = state.cfg;
        closePanel(true);
        if (item.kind === 'dm') { if (cfg.openDm) cfg.openDm(item.conversation_id); return; }
        if (cfg.jumpToMessage) cfg.jumpToMessage(item.channel_id, item.message_id);
    }

    function showEmpty() {
        var p = state.panel;
        if (!p) return;
        p.status.textContent = 'Nothing saved yet. Choose Save message in the menu of a message (right-click, the menu key on a focused message, or the ... button on a touch screen).';
    }

    function loadPage(first) {
        var p = state.panel;
        if (!p) return Promise.resolve();
        var path = '/api/saved?limit=30' + (!first && state.nextBefore ? '&before_id=' + state.nextBefore : '');
        p.status.textContent = 'Loading';
        p.more.style.display = 'none';
        return api('GET', path).then(function (res) {
            if (state.panel !== p) return;
            if (res.status !== 200) { p.status.textContent = errorText(res, 'The saved messages could not be loaded.'); return; }
            if (res.data.limits) state.limits = res.data.limits;
            if (first) { p.list.textContent = ''; state.items = new Map(); }
            (res.data.items || []).forEach(function (it) { p.list.appendChild(renderItem(it)); });
            state.nextBefore = res.data.has_more ? res.data.next_before_id : null;
            p.more.style.display = state.nextBefore ? '' : 'none';
            p.status.textContent = '';
            if (!p.list.children.length) showEmpty();
        }).catch(function () {
            if (state.panel === p) p.status.textContent = 'The saved messages could not be loaded.';
        });
    }

    function openPanel() {
        if (state.panel) return state.panel;
        var overlay = el('div', '', 'saved-overlay');
        var dlg = el('div', '', 'saved-panel', { role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'saved-title' });
        var head = el('div', '', 'saved-head');
        var title = el('h2', 'Saved messages', 'saved-title', { id: 'saved-title', tabindex: '-1' });
        var close = button('Close', 'btn-secondary', function () { closePanel(false); }, { 'data-action': 'close' });
        head.append(title, close);
        var note = el('p', 'Only you can see what you save. A saved message shows what you can read now; if it was deleted or you lost access, it says so.', 'saved-meta');
        var status = el('p', '', 'saved-meta', { role: 'status' });
        var list = el('div', '', 'saved-list', { role: 'list' });
        var more = button('Load more', 'btn-secondary', function () { loadPage(false); }, { 'data-action': 'more' });
        more.style.display = 'none';
        dlg.append(head, note, status, list, more);
        overlay.appendChild(dlg);
        overlay.addEventListener('click', function (e) { if (e.target === overlay) closePanel(false); });
        doc().body.appendChild(overlay);
        state.opener = doc().activeElement;
        state.panel = { node: overlay, dlg: dlg, list: list, status: status, more: more, title: title };
        if (title.focus) title.focus();
        loadPage(true);
        return state.panel;
    }

    function closePanel(skipFocus) {
        closeRemind();
        var p = state.panel;
        if (!p) return;
        state.panel = null;
        state.items = new Map();
        if (p.node.parentNode) p.node.parentNode.removeChild(p.node);
        var opener = state.opener;
        state.opener = null;
        if (!skipFocus && opener && opener.focus) opener.focus();
    }

    /* Escape closes the top dialog; Tab stays inside it. */
    function onKeydown(e) {
        var top = state.remind || state.panel;
        if (!top) return;
        if (e.key === 'Escape') {
            e.preventDefault();
            if (state.remind) closeRemind(); else closePanel(false);
            return;
        }
        if (e.key !== 'Tab' || !top.dlg.querySelectorAll) return;
        var items = Array.prototype.filter.call(top.dlg.querySelectorAll('button, input'),
            function (n) { return !n.disabled && n.style.display !== 'none'; });
        if (!items.length) return;
        var first = items[0], last = items[items.length - 1], active = doc().activeElement;
        if (e.shiftKey && (active === first || !top.dlg.contains(active))) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && (active === last || !top.dlg.contains(active))) { e.preventDefault(); first.focus(); }
    }

    /* ---------------------------------------------------------------- keyboard: reach a message and its menu */
    function messageRows(container) {
        return Array.prototype.slice.call(container.querySelectorAll('.message[data-message-id]:not(.system)'));
    }

    function focusRow(row) {
        if (!row) return;
        row.setAttribute('tabindex', '-1');
        row.focus();
        if (row.scrollIntoView) row.scrollIntoView({ block: 'nearest' });
    }

    /* The menu the page opens on a context-menu event for `row`, here from the keyboard or the actions
     * button. `anchor` (the button) sets where it opens and where focus returns when it closes. */
    function openMenuAt(row, anchor) {
        var rect = (anchor || row).getBoundingClientRect();
        var ev = new root.MouseEvent('contextmenu', {
            bubbles: true, cancelable: true,
            clientX: Math.round(rect.left + (anchor ? 0 : 24)), clientY: Math.round(rect.top + (anchor ? (rect.height || 0) : 16))
        });
        row.dispatchEvent(ev);
        var menu = doc().getElementById('message-context-menu');
        if (menu && menu.classList.contains('show')) {
            state.menuReturn = anchor || row;
            var items = menuItems(menu);
            if (items.length) items[0].focus();
        }
    }

    function menuItems(menu) {
        return Array.prototype.filter.call(menu.querySelectorAll('.context-menu-item'), function (n) {
            return n.style.display !== 'none';
        }).map(function (n) { n.setAttribute('tabindex', '-1'); n.setAttribute('role', 'menuitem'); return n; });
    }

    function onMessagesKeydown(e) {
        var container = e.currentTarget;
        if (e.target === container) {
            if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
                var all = messageRows(container);
                if (all.length) { e.preventDefault(); focusRow(e.key === 'ArrowUp' ? all[all.length - 1] : all[0]); }
            }
            return;
        }
        var row = e.target.closest ? e.target.closest('.message[data-message-id]') : null;
        if (!row || e.target !== row) return;
        if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
            var rows = messageRows(container);
            var i = rows.indexOf(row) + (e.key === 'ArrowUp' ? -1 : 1);
            if (i >= 0 && i < rows.length) { e.preventDefault(); focusRow(rows[i]); }
        } else if (e.key === 'ContextMenu' || (e.key === 'F10' && e.shiftKey)) {
            e.preventDefault();
            openMenuAt(row);
        }
    }

    /* The button's own click. It must not reach the page's click handler, which closes the menus. */
    function onMessagesClick(e) {
        var btn = e.target && e.target.closest ? e.target.closest('.msg-actions-btn') : null;
        if (!btn) return;
        e.preventDefault();
        e.stopPropagation();
        var row = btn.closest('.message[data-message-id]');
        if (row) openMenuAt(row, btn);
    }

    function onMenuKeydown(e) {
        var menu = e.currentTarget;
        var items = menuItems(menu);
        var i = items.indexOf(doc().activeElement);
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault();
            if (!items.length) return;
            i = e.key === 'ArrowDown' ? (i + 1) % items.length : (i <= 0 ? items.length - 1 : i - 1);
            items[i].focus();
        } else if ((e.key === 'Enter' || e.key === ' ') && i >= 0) {
            e.preventDefault();
            items[i].click();
        } else if (e.key === 'Escape' || e.key === 'Tab') {
            e.preventDefault();
            if (state.cfg.hideMenus) state.cfg.hideMenus();
            if (state.menuReturn && state.menuReturn.focus) state.menuReturn.focus();
        }
    }

    /* ---------------------------------------------------------------- start */
    function init(cfg) {
        state.cfg = cfg;
        state.doc = cfg.doc || null;
        var d = doc();
        var save = d.getElementById(MENU_SAVE_ID);
        if (save) save.addEventListener('click', toggleCurrent);
        var remind = d.getElementById(MENU_REMIND_ID);
        if (remind) remind.addEventListener('click', remindCurrent);
        var openBtn = d.getElementById(OPEN_BUTTON_ID);
        if (openBtn) openBtn.addEventListener('click', openPanel);
        d.addEventListener('keydown', onKeydown);
        var container = d.getElementById('chat-messages');
        if (container) {
            if (!container.getAttribute('tabindex')) container.setAttribute('tabindex', '0');
            container.setAttribute('aria-label', 'Messages');
            container.addEventListener('keydown', onMessagesKeydown);
            container.addEventListener('click', onMessagesClick);
            if (typeof root.MutationObserver === 'function') {
                state.observer = new root.MutationObserver(function (records) {
                    records.forEach(function (r) {
                        Array.prototype.forEach.call(r.addedNodes || [], function (n) {
                            if (n.classList && n.classList.contains('message')) decorate(n);
                        });
                    });
                });
                state.observer.observe(container, { childList: true });
            }
        }
        var menu = d.getElementById('message-context-menu');
        if (menu) menu.addEventListener('keydown', onMenuKeydown);
        d.addEventListener('visibilitychange', function () { if (!d.hidden) refreshMarks(); });
        /* the actions button does not depend on the marks: rows already on the page get it even when the marks
         * cannot be loaded (a limit, the network) */
        decorateAll();
        return loadMarks();
    }

    var apiOut = {
        init: init, open: openPanel, close: function () { closePanel(false); }, prepareMenu: prepareMenu,
        decorateAll: decorateAll, loadMarks: loadMarks, refreshMarks: refreshMarks,
        utcIso: utcIso, remindChoices: remindChoices, parseLocalInput: parseLocalInput,
        whenProblem: whenProblem, formatWhen: formatWhen, localInputValue: localInputValue,
        _state: state
    };
    if (typeof module !== 'undefined' && module.exports) module.exports = apiOut;
    root.ChatSaved = apiOut;
})(typeof window !== 'undefined' ? window : globalThis);

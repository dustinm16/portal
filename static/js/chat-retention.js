/* Channel retention and the prune tool of the chat page.
 *
 *  - Administrators get a Retention button (the channel's own message and file retention, with a
 *    confirmation that shows the count when a change would remove more).
 *  - Moderators of the open chat (and administrators) get a Prune button: range, optional user,
 *    keep pinned; the count of a dry run is shown before anything is removed.
 *  - A channel with its own retention shows "messages older than N days are removed, next cleanup
 *    about <time>" under the topic.
 *
 * The page calls onChannelInfo (the channel_info frame), onModLevel (the mod_level frame) and
 * removes pruned messages itself (messages_pruned). Pure helpers are exported for tests under Node
 * (tests/retention_harness.js). No inline handlers: every control is bound with addEventListener.
 */
(function (root) {
    'use strict';

    // ---- pure helpers ------------------------------------------------------------------------

    function dayWord(n) { return n === 1 ? 'day' : 'days'; }

    function timeText(ms, nowMs) {
        var d = new Date(ms);
        var now = new Date(nowMs == null ? Date.now() : nowMs);
        var sameDay = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
        var hm = ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
        if (sameDay) return hm;
        return d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2) + '-' + ('0' + d.getDate()).slice(-2) + ' ' + hm;
    }

    /* The line of the channel info; empty when the channel follows the global setting. */
    function noticeText(days, nextIso, nowMs) {
        if (days === null || days === undefined) return '';
        var text = 'Messages older than ' + days + ' ' + dayWord(days) + ' are removed';
        var ms = nextIso ? Date.parse(nextIso) : NaN;
        if (isFinite(ms)) {
            text += ms < (nowMs == null ? Date.now() : nowMs) ? ', next cleanup is due' : ', next cleanup about ' + timeText(ms, nowMs);
        }
        return text + '.';
    }

    /* One retention field as typed: '' = follow the global setting (null), 'forever' or 0 = the
     * cap, a whole number of days. Returns {ok, value} or {ok:false}. */
    function parseDays(text) {
        var t = String(text == null ? '' : text).trim().toLowerCase();
        if (t === '') return { ok: true, value: null };
        if (t === 'forever') return { ok: true, value: 'forever' };
        if (/^\d{1,5}$/.test(t)) return { ok: true, value: parseInt(t, 10) };
        return { ok: false };
    }

    function retentionBody(messageText, fileText, confirm) {
        var m = parseDays(messageText), f = parseDays(fileText);
        if (!m.ok || !f.ok) return { ok: false, error: 'Enter a number of days, "forever", or leave the field empty.' };
        var body = { retention_days: m.value, file_retention_days: f.value };
        if (confirm) body.confirm = true;
        return { ok: true, body: body };
    }

    /* "2 messages and 1 file ..." for the confirm window; counts come from the dry-run answer. */
    function confirmText(resp) {
        var parts = [];
        var m = resp && resp.would_remove_messages, f = resp && resp.would_remove_files;
        if (m !== undefined && m !== null) parts.push(m + (m === 1 ? ' message' : ' messages'));
        if (f !== undefined && f !== null) parts.push(f + (f === 1 ? ' file' : ' files'));
        return 'The next cleanup would remove ' + (parts.length ? parts.join(' and ') : 'older content') +
            ' from this channel (pinned messages stay). Apply this retention?';
    }

    /* A <input type="datetime-local"> value (local time) as the UTC ISO string the server expects. */
    function localToIso(value) {
        if (!value) return '';
        var d = new Date(value);
        return isNaN(d.getTime()) ? '' : d.toISOString();
    }

    function localInputValue(ms) {
        var d = new Date(ms);
        function p(n) { return ('0' + n).slice(-2); }
        return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' + p(d.getMinutes());
    }

    function pruneBody(opts) {
        var from = localToIso(opts.from), to = localToIso(opts.to);
        if (!from || !to) return { ok: false, error: 'Choose both the start and the end of the range.' };
        if (from > to) return { ok: false, error: 'The start must not be after the end.' };
        var body = { from: from, to: to, skip_pinned: opts.skipPinned !== false };
        var user = String(opts.user || '').trim();
        if (user) body.user = user;
        if (opts.dryRun) body.dry_run = true;
        if (opts.expected !== undefined && opts.expected !== null) body.expected_count = opts.expected;
        return { ok: true, body: body };
    }

    function pruneCountText(n, skipPinned) {
        return n === 0 ? 'No messages match.' :
            n + (n === 1 ? ' message' : ' messages') + ' would be removed' + (skipPinned ? ' (pinned messages are kept).' : ' (pinned messages included).');
    }

    var api = { noticeText: noticeText, parseDays: parseDays, retentionBody: retentionBody, confirmText: confirmText,
                localToIso: localToIso, localInputValue: localInputValue, pruneBody: pruneBody, pruneCountText: pruneCountText };

    // ---- the page ----------------------------------------------------------------------------

    var cur = null;          // the open channel: {id, name, level, role, stream_chat, retention_days, ...}
    var ui = {};

    function el(tag, attrs, text) {
        var e = document.createElement(tag);
        Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
        if (text) e.textContent = text;
        return e;
    }

    function toast(message, kind) {
        if (root.Portal && root.Portal.toast) root.Portal.toast(message, kind || 'info');
    }

    function ensureStyle() {
        if (document.getElementById('chat-retention-style')) return;
        var st = el('style', { id: 'chat-retention-style' });
        st.textContent =
            '.cr-btn{background:none;border:1px solid var(--border);color:var(--text-muted);cursor:pointer;padding:0.25rem 0.5rem;border-radius:4px;font-size:0.75rem}' +
            '.cr-btn:hover{background:rgba(255,255,255,0.08)}' +
            '.cr-note{color:var(--text-muted);font-size:0.75rem;margin-top:0.15rem}' +
            '.cr-modal .modal-content{max-width:440px}' +
            '.cr-field{margin-bottom:0.75rem;display:flex;flex-direction:column;gap:0.25rem}' +
            '.cr-field label{font-size:0.8rem;color:var(--text-secondary)}' +
            '.cr-field input[type=text],.cr-field input[type=datetime-local]{background:rgba(0,0,0,0.3);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);padding:0.4rem;box-sizing:border-box;width:100%}' +
            '.cr-help{font-size:0.75rem;color:var(--text-muted)}' +
            '.cr-result{font-size:0.85rem;margin:0.5rem 0;min-height:1.2em}' +
            '.cr-actions{display:flex;gap:0.5rem;justify-content:flex-end;margin-top:0.75rem}';
        document.head.appendChild(st);
    }

    function dialog(title, bodyNodes, actions) {
        ensureStyle();
        var modal = el('div', { 'class': 'modal cr-modal', role: 'dialog', 'aria-modal': 'true' });
        var backdrop = el('div', { 'class': 'modal-backdrop' });
        var content = el('div', { 'class': 'modal-content' });
        var header = el('div', { 'class': 'modal-header' });
        header.appendChild(el('h3', {}, title));
        var close = el('button', { 'class': 'modal-close', type: 'button', 'aria-label': 'Close' }, '×');
        header.appendChild(close);
        content.appendChild(header);
        bodyNodes.forEach(function (n) { content.appendChild(n); });
        var bar = el('div', { 'class': 'cr-actions' });
        actions.forEach(function (a) { bar.appendChild(a); });
        content.appendChild(bar);
        modal.appendChild(backdrop);
        modal.appendChild(content);
        function shut() { if (modal.parentNode) modal.parentNode.removeChild(modal); }
        backdrop.addEventListener('click', shut);
        close.addEventListener('click', shut);
        modal.style.display = 'flex';
        document.body.appendChild(modal);
        return { modal: modal, close: shut };
    }

    function field(labelText, input, help) {
        var wrap = el('div', { 'class': 'cr-field' });
        var id = 'cr-' + Math.random().toString(36).slice(2, 8);
        input.id = id;
        var lab = el('label', { 'for': id }, labelText);
        wrap.appendChild(lab);
        wrap.appendChild(input);
        if (help) wrap.appendChild(el('div', { 'class': 'cr-help' }, help));
        return wrap;
    }

    async function send(method, url, body) {
        var resp = await fetch(url, { method: method, credentials: 'include',
            headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
        var data = null;
        try { data = await resp.json(); } catch (e) { data = null; }
        return { status: resp.status, ok: resp.ok, data: data || {} };
    }

    // -- retention (administrators)
    function openRetention() {
        if (!cur) return;
        var chan = cur;
        var msg = el('input', { type: 'text', inputmode: 'numeric', placeholder: 'empty = follow the global setting' });
        msg.value = chan.retention_days == null ? '' : String(chan.retention_days);
        var files = el('input', { type: 'text', inputmode: 'numeric', placeholder: 'empty = files stay with their messages' });
        files.value = chan.file_retention_days == null ? '' : String(chan.file_retention_days);
        var result = el('div', { 'class': 'cr-result', role: 'status' });
        var save = el('button', { 'class': 'btn btn-primary', type: 'button' }, 'Save');
        var cancel = el('button', { 'class': 'btn btn-secondary', type: 'button' }, 'Cancel');
        var d = dialog('Retention of #' + chan.name, [
            field('Remove messages older than (days)', msg,
                'A number of days, or "forever" (the longest the portal allows). Pinned messages are kept.'),
            field('Remove uploaded files older than (days)', files,
                'The message stays and is marked "file removed". Never longer than the message value.'),
            result], [cancel, save]);
        cancel.addEventListener('click', d.close);
        save.addEventListener('click', async function () {
            var parsed = retentionBody(msg.value, files.value, false);
            if (!parsed.ok) { result.textContent = parsed.error; return; }
            save.disabled = true;
            try {
                var url = '/api/chat/channels/' + encodeURIComponent(chan.id) + '/retention';
                var r = await send('PUT', url, parsed.body);
                if (r.ok && r.data.confirm_required) {
                    if (!root.confirm(confirmText(r.data))) { result.textContent = 'Nothing was changed.'; return; }
                    parsed = retentionBody(msg.value, files.value, true);
                    r = await send('PUT', url, parsed.body);
                }
                if (!r.ok) { result.textContent = (r.data && r.data.error) || 'The change was refused.'; return; }
                chan.retention_days = r.data.retention_days;
                chan.file_retention_days = r.data.file_retention_days;
                chan.retention_next_cleanup = r.data.next_cleanup_at || chan.retention_next_cleanup;
                renderNotice();
                toast('Retention saved', 'success');
                d.close();
                if (typeof root.loadChannels === 'function') root.loadChannels();
            } catch (e) {
                result.textContent = 'The change could not be sent.';
            } finally {
                save.disabled = false;
            }
        });
    }

    // -- prune (moderators and administrators)
    function openPrune() {
        if (!cur) return;
        var chan = cur;
        var now = Date.now();
        var from = el('input', { type: 'datetime-local' });
        from.value = localInputValue(now - 3600 * 1000);
        var to = el('input', { type: 'datetime-local' });
        to.value = localInputValue(now);
        var user = el('input', { type: 'text', placeholder: 'optional: a username' });
        var pinWrap = el('div', { 'class': 'cr-field' });
        var pin = el('input', { type: 'checkbox' });
        pin.checked = true;
        var pinLab = el('label', {}, ' Keep pinned messages');
        pinLab.insertBefore(pin, pinLab.firstChild);
        pinWrap.appendChild(pinLab);
        var result = el('div', { 'class': 'cr-result', role: 'status' });
        var count = el('button', { 'class': 'btn btn-secondary', type: 'button' }, 'Count');
        var run = el('button', { 'class': 'btn btn-primary', type: 'button' }, 'Remove');
        run.disabled = true;
        var cancel = el('button', { 'class': 'btn btn-secondary', type: 'button' }, 'Close');
        var counted = null;      // the dry-run count the Remove button will echo
        var d = dialog('Prune #' + chan.name, [
            field('From', from), field('To', to), field('Only messages of (optional)', user,
                'Count first: nothing is removed until you confirm the number shown.'),
            pinWrap, result], [cancel, count, run]);
        function invalidate() { counted = null; run.disabled = true; run.textContent = 'Remove'; }
        [from, to, user, pin].forEach(function (c) { c.addEventListener('input', invalidate); c.addEventListener('change', invalidate); });
        cancel.addEventListener('click', d.close);
        var url = '/api/chat/channels/' + encodeURIComponent(chan.id) + '/prune';
        function opts(extra) {
            return pruneBody(Object.assign({ from: from.value, to: to.value, user: user.value, skipPinned: pin.checked }, extra));
        }
        count.addEventListener('click', async function () {
            var p = opts({ dryRun: true });
            if (!p.ok) { result.textContent = p.error; return; }
            count.disabled = true;
            try {
                var r = await send('POST', url, p.body);
                if (!r.ok) { result.textContent = (r.data && r.data.error) || 'The count was refused.'; return; }
                counted = r.data.count;
                result.textContent = pruneCountText(counted, pin.checked);
                run.disabled = counted === 0;
                run.textContent = 'Remove ' + counted;
            } catch (e) {
                result.textContent = 'The count could not be sent.';
            } finally {
                count.disabled = false;
            }
        });
        run.addEventListener('click', async function () {
            if (counted === null) return;
            var p = opts({ expected: counted });
            if (!p.ok) { result.textContent = p.error; return; }
            if (!root.confirm('Remove ' + counted + (counted === 1 ? ' message' : ' messages') + ' from #' + chan.name + '? This cannot be undone.')) return;
            run.disabled = true;
            try {
                var r = await send('POST', url, p.body);
                if (r.status === 409 && r.data && r.data.count !== undefined) {
                    counted = null;
                    result.textContent = (r.data.error || 'The count changed.') + ' Now ' + r.data.count + '; count again.';
                    return;
                }
                if (!r.ok) { result.textContent = (r.data && r.data.error) || 'The prune was refused.'; return; }
                toast('Prune started: ' + r.data.count + ' messages', 'success');
                d.close();
                watch(chan.id);
            } catch (e) {
                result.textContent = 'The prune could not be sent.';
            }
        });
    }

    // After a prune started: tell the person who started it when it is done.
    async function watch(channelId) {
        for (var i = 0; i < 600; i++) {
            await new Promise(function (resolve) { setTimeout(resolve, 1000); });
            try {
                var r = await send('GET', '/api/chat/channels/' + encodeURIComponent(channelId) + '/prune');
                if (r.ok && r.data && r.data.running === false) {
                    toast(r.data.status === 'completed' ? 'Prune finished: ' + r.data.removed + ' messages removed'
                        : 'Prune ' + (r.data.status || 'ended') + ' after ' + (r.data.removed || 0) + ' messages',
                        r.data.status === 'completed' ? 'success' : 'error');
                    return;
                }
            } catch (e) { return; }
        }
    }

    // -- header controls and notice
    function ensureControls() {
        if (ui.ready || typeof document === 'undefined') return !!ui.ready;
        var anchor = document.getElementById('clear-channel-btn');
        var topic = document.getElementById('channel-topic');
        if (!anchor || !topic) return false;
        ensureStyle();
        ui.retention = el('button', { 'class': 'cr-btn', type: 'button', id: 'retention-btn', title: 'Retention of this channel' }, 'Retention');
        ui.prune = el('button', { 'class': 'cr-btn', type: 'button', id: 'prune-btn', title: 'Remove messages in a date range' }, 'Prune');
        ui.retention.style.display = 'none';
        ui.prune.style.display = 'none';
        anchor.parentNode.insertBefore(ui.retention, anchor);
        anchor.parentNode.insertBefore(ui.prune, anchor);
        ui.note = el('div', { 'class': 'cr-note', id: 'retention-note' });
        ui.note.style.display = 'none';
        topic.parentNode.insertBefore(ui.note, topic.nextSibling);
        ui.retention.addEventListener('click', openRetention);
        ui.prune.addEventListener('click', openPrune);
        ui.ready = true;
        return true;
    }

    function isAdmin(user) { return !!user && (user.role === 'admin' || user.role === 'superadmin'); }

    function renderButtons() {
        if (!ensureControls()) return;
        var open = !!cur;
        ui.prune.style.display = open && cur.level && cur.level !== 'none' ? '' : 'none';
        // a stream's chat keeps the global retention; only administrators set it elsewhere
        ui.retention.style.display = open && isAdmin(cur.user) && !cur.stream_chat ? '' : 'none';
    }

    function renderNotice() {
        if (!ensureControls()) return;
        var text = cur && !cur.stream_chat ? noticeText(cur.retention_days, cur.retention_next_cleanup) : '';
        ui.note.textContent = text;
        ui.note.style.display = text ? '' : 'none';
    }

    function onChannelInfo(data, user) {
        if (!data) { cur = null; } else {
            cur = { id: data.id, name: data.name, level: data.mod_level || 'none', user: user || null,
                    stream_chat: !!data.stream_chat, retention_days: data.retention_days == null ? null : data.retention_days,
                    file_retention_days: data.file_retention_days == null ? null : data.file_retention_days,
                    retention_next_cleanup: data.retention_next_cleanup || null };
        }
        renderButtons();
        renderNotice();
    }

    function onModLevel(level, user) {
        if (cur) { cur.level = level || 'none'; if (user) cur.user = user; }
        renderButtons();
    }

    api.onChannelInfo = onChannelInfo;
    api.onModLevel = onModLevel;
    root.ChatRetention = api;
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);

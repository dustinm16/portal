/*
 * Stream schedule (1.23.0): the countdown and Interested toggle on the watch page while a stream is offline,
 * the Upcoming strip on the Streams page, the owner's schedule editor in the stream settings and the calendar
 * feed block of the user settings.
 *
 *   StreamSchedule.mountWatch(el, stream, user)    countdown + Interested for the next occurrence
 *   StreamSchedule.mountUpcoming(el)               the Upcoming strip
 *   StreamSchedule.mountOwner(el, streamId, done)  the owner's editor (done(title): called after the title is applied)
 *   StreamSchedule.mountFeed(el)                   the calendar link: create, regenerate, revoke
 *
 * Every piece of text that came from the server goes in through textContent; nothing here assigns innerHTML and no
 * inline handler is made. The page elements #schedule-upcoming and #calendar-feed-settings mount themselves.
 */
(function () {
    'use strict';

    var FEED_WARNING = 'The link holds a secret in its address. Web proxies and servers between you and the portal ' +
        'can log an address, and anyone who has the link can read your schedule feed until you regenerate or ' +
        'revoke it. Treat it like a password and regenerate it if it may have leaked.';

    function el(tag, props, kids) {
        var n = document.createElement(tag);
        Object.keys(props || {}).forEach(function (k) {
            if (k === 'text') n.textContent = props[k];
            else if (k === 'class') n.className = props[k];
            else if (k === 'on') Object.keys(props.on).forEach(function (t) { n.addEventListener(t, props.on[t]); });
            else if (k === 'style') Object.keys(props.style).forEach(function (s) { n.style[s] = props.style[s]; });
            else if (k === 'value' || k === 'checked' || k === 'disabled' || k === 'type') n[k] = props[k];
            else n.setAttribute(k, props[k]);
        });
        (kids || []).forEach(function (c) { if (c) n.appendChild(c); });
        return n;
    }

    function clear(n) { n.textContent = ''; }

    function toast(msg, kind) {
        if (window.Portal && typeof window.Portal.toast === 'function') window.Portal.toast(msg, kind);
    }

    async function api(method, url, body) {
        var init = { method: method, credentials: 'include', headers: { 'Accept': 'application/json' } };
        if (body !== undefined) {
            init.headers['Content-Type'] = 'application/json';
            init.body = JSON.stringify(body);
        }
        try {
            var resp = await fetch(url, init);
            var data = null;
            try { data = await resp.json(); } catch (e) { data = null; }
            return { ok: resp.ok, status: resp.status, data: data || {} };
        } catch (e) {
            return { ok: false, status: 0, data: { error: 'Network error' } };
        }
    }

    function errorOf(r, fallback) { return (r && r.data && r.data.error) || fallback; }

    // ---- pure helpers (also what the tests read)
    function pad(n) { return (n < 10 ? '0' : '') + n; }

    /* 93784 -> "1 day 2:03:04" ; under a day "2:03:04" ; zero or less "Starting now" */
    function countdownText(seconds) {
        seconds = Math.floor(seconds);
        if (seconds <= 0) return 'Starting now';
        var d = Math.floor(seconds / 86400), h = Math.floor((seconds % 86400) / 3600);
        var m = Math.floor((seconds % 3600) / 60), s = seconds % 60;
        var clock = h + ':' + pad(m) + ':' + pad(s);
        if (d > 0) return d + (d === 1 ? ' day ' : ' days ') + clock;
        return clock;
    }

    function whenText(epoch) {
        try {
            return new Date(epoch * 1000).toLocaleString([], { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
        } catch (e) { return new Date(epoch * 1000).toISOString(); }
    }

    function rsvpUrl(item) {
        return '/api/streams/' + Number(item.stream_id) + '/schedule/' + Number(item.entry_id) + '/rsvp/' + Number(item.start);
    }

    function interestedButton(item, onChange) {
        var btn = el('button', { type: 'button', class: 'btn btn-sm btn-secondary schedule-interested' });
        function show(on) {
            btn.setAttribute('aria-pressed', String(on));
            btn.textContent = on ? 'Interested - reminder set' : 'Interested';
            btn.setAttribute('title', on ? 'Take the reminder back' : 'Remind me 10 minutes before it starts');
        }
        show(!!item.interested);
        btn.addEventListener('click', async function () {
            var on = btn.getAttribute('aria-pressed') !== 'true';
            btn.disabled = true;
            var r = await api(on ? 'POST' : 'DELETE', rsvpUrl(item));
            btn.disabled = false;
            if (r.ok) { item.interested = on; show(on); if (onChange) onChange(on); }
            else toast(errorOf(r, 'Could not change this'), 'error');
        });
        return btn;
    }

    // ---- the watch page, offline
    async function mountWatch(container, stream, user) {
        if (!container || !stream) return null;
        var r = await api('GET', '/api/streams/' + Number(stream.id) + '/schedule');
        if (!r.ok || !r.data.next || !r.data.next.length) return null;
        var item = r.data.next[0];
        var skew = (r.data.now || 0) * 1000 - Date.now();
        var countdown = el('div', { class: 'schedule-countdown', style: { fontSize: '1.4rem', fontVariantNumeric: 'tabular-nums' } });
        var box = el('div', { class: 'schedule-box', style: { marginTop: '1rem', textAlign: 'center' } }, [
            el('div', { class: 'schedule-label', text: 'Next stream' }),
            el('div', { class: 'schedule-title', text: item.title, style: { fontWeight: '600' } }),
            el('div', { class: 'schedule-when', text: whenText(item.start) }),
            countdown
        ]);
        var memberMayMark = user && stream.user_id !== user.id;
        var markRow = null;
        if (memberMayMark) {
            markRow = el('div', { class: 'schedule-mark', style: { marginTop: '0.5rem' } }, [interestedButton(item)]);
            box.appendChild(markRow);
        }
        function tick() {
            var left = item.start - (Date.now() + skew) / 1000;
            countdown.textContent = countdownText(left);
            /* the route refuses a mark once the start has passed, so the toggle goes with it */
            if (markRow && left <= 0) { markRow.style.display = 'none'; markRow = null; }
            if (container.isConnected === false) { clearInterval(timer); }
        }
        container.appendChild(box);
        tick();
        var timer = setInterval(tick, 1000);
        return { box: box, item: item, stop: function () { clearInterval(timer); } };
    }

    // ---- the Upcoming strip
    async function mountUpcoming(container) {
        if (!container) return;
        var r = await api('GET', '/api/streams/schedule/upcoming?limit=12');
        clear(container);
        var list = (r.ok && r.data.occurrences) || [];
        container.style.display = list.length ? '' : 'none';
        if (!list.length) return;
        container.appendChild(el('h3', { text: 'Upcoming', style: { margin: '0 0 0.5rem' } }));
        var row = el('div', { class: 'schedule-strip', style: { display: 'flex', gap: '0.75rem', overflowX: 'auto' } });
        list.forEach(function (item) {
            var card = el('div', { class: 'schedule-card', style: { minWidth: '14rem', padding: '0.6rem', border: '1px solid var(--card-border)', borderRadius: '8px' } }, [
                el('div', { text: item.title, style: { fontWeight: '600' } }),
                el('div', { text: item.streamer + (item.recurring ? ' - weekly' : '') }),
                el('div', { text: whenText(item.start) }),
                el('a', { class: 'btn btn-sm btn-secondary', href: '/watch/' + Number(item.stream_id), text: 'Open the stream', style: { marginTop: '0.4rem' } })
            ]);
            if (item.interested_count === undefined) card.appendChild(el('div', { style: { marginTop: '0.4rem' } }, [interestedButton(item)]));
            else card.appendChild(el('div', { text: item.interested_count + ' interested', style: { marginTop: '0.4rem' } }));
            row.appendChild(card);
        });
        container.appendChild(row);
    }

    // ---- the owner's editor
    function defaultZone() {
        try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch (e) { return 'UTC'; }
    }

    function describeEntry(e) {
        var local = String(e.start || '');
        var when = local.replace('T', ' ');
        return e.title + ' - ' + (e.recurrence === 'weekly' ? 'every week from ' : '') + when + ' (' + e.tz + '), ' + e.duration_min + ' min';
    }

    async function mountOwner(container, streamId, done) {
        if (!container) return;
        var sid = Number(streamId);
        var base = '/api/streams/' + sid + '/schedule';

        async function load() {
            var r = await api('GET', base);
            clear(container);
            if (!r.ok) { container.appendChild(el('p', { text: errorOf(r, 'The schedule could not be loaded.') })); return; }
            render(r.data);
        }

        async function act(method, url, body, okMsg) {
            var r = await api(method, url, body);
            if (!r.ok) { toast(errorOf(r, 'That did not work'), 'error'); return r; }
            if (okMsg) toast(okMsg, 'success');
            await load();
            return r;
        }

        function render(data) {
            if (data.suggestion) {
                var s = data.suggestion;
                container.appendChild(el('div', { class: 'schedule-suggestion', style: { marginBottom: '0.75rem' } }, [
                    el('div', { text: 'You went live for the slot "' + s.title + '". Use it as the stream title?' }),
                    el('button', { type: 'button', class: 'btn btn-sm btn-primary', text: 'Use this title', on: { click: async function () {
                        var u = await api('PUT', '/api/streams/' + sid, { name: s.title });
                        if (!u.ok) { toast(errorOf(u, 'The title could not be changed'), 'error'); return; }
                        await api('DELETE', base + '/suggestion');
                        toast('Title changed', 'success');
                        if (done) done(s.title);
                        await load();
                    } } }),
                    el('button', { type: 'button', class: 'btn btn-sm btn-secondary', text: 'Dismiss', on: { click: function () {
                        act('DELETE', base + '/suggestion');
                    } } })
                ]));
            }
            (data.entries || []).forEach(function (e) {
                var item = el('div', { class: 'schedule-entry', style: { marginBottom: '0.6rem' } }, [el('div', { text: describeEntry(e) })]);
                if (e.problem) item.appendChild(el('div', { class: 'schedule-problem', style: { marginLeft: '1rem', color: 'var(--danger, #c0392b)' }, text: String(e.problem) + ' - choose another zone' }));
                (e.next || []).slice(0, 2).forEach(function (n) {
                    item.appendChild(el('div', { style: { marginLeft: '1rem' } }, [
                        el('span', { text: whenText(n.start) + ' - ' + n.interested_count + ' interested ' }),
                        el('button', { type: 'button', class: 'btn btn-sm btn-secondary', text: 'Cancel this one', on: { click: function () {
                            act('POST', base + '/' + Number(e.id) + '/cancel/' + Number(n.start), undefined, 'Occurrence cancelled');
                        } } })
                    ]));
                });
                (e.cancelled || []).forEach(function (c) {
                    item.appendChild(el('div', { style: { marginLeft: '1rem' } }, [
                        el('span', { text: 'Cancelled: ' + whenText(c) + ' ' }),
                        el('button', { type: 'button', class: 'btn btn-sm btn-secondary', text: 'Restore', on: { click: function () {
                            act('DELETE', base + '/' + Number(e.id) + '/cancel/' + Number(c));
                        } } })
                    ]));
                });
                item.appendChild(el('button', { type: 'button', class: 'btn btn-sm btn-danger', text: 'Delete the whole entry', on: { click: function () {
                    act('DELETE', base + '/' + Number(e.id), undefined, 'Entry deleted');
                } } }));
                container.appendChild(item);
            });
            if (!(data.entries || []).length) container.appendChild(el('p', { text: 'Nothing is scheduled.' }));

            var lim = data.limits || {};
            var idp = 'schedule-' + sid + '-';
            var title = el('input', { type: 'text', id: idp + 'title', maxlength: String(lim.title || 100), placeholder: 'Title of the slot' });
            var start = el('input', { type: 'datetime-local', id: idp + 'start' });
            var tz = el('input', { type: 'text', id: idp + 'tz', value: defaultZone(), maxlength: '64' });
            var dur = el('input', { type: 'number', id: idp + 'dur', value: '60', min: '5', max: '1440' });
            var weekly = el('input', { type: 'checkbox', id: idp + 'weekly', checked: true });
            /* the form classes of the stream settings: one label and one field per row, the field in the dark theme's look */
            function row(labelText, field) {
                return el('div', { class: 'form-group' }, [el('label', { 'for': field.id, text: labelText }), field]);
            }
            container.appendChild(el('div', { class: 'schedule-form', style: { marginTop: '0.75rem' } }, [
                row('Title', title),
                row('Start (read in the time zone chosen below)', start),
                row('Time zone (for example Europe/Berlin)', tz),
                row('Minutes', dur),
                el('div', { class: 'form-group' }, [
                    el('label', { class: 'checkbox-label', 'for': weekly.id, style: { display: 'flex' } }, [weekly, el('span', { text: 'Repeats every week at this local time' })])
                ]),
                el('button', { type: 'button', class: 'btn btn-sm btn-primary', text: 'Add to the schedule', on: { click: function () {
                    act('POST', base, { title: title.value, start: start.value, tz: tz.value.trim(),
                                        duration_min: parseInt(dur.value, 10), recurrence: weekly.checked ? 'weekly' : null },
                        'Added to the schedule');
                } } })
            ]));
        }
        await load();
    }

    // ---- the calendar feed block of the user settings
    async function mountFeed(container) {
        if (!container) return;
        async function load() {
            var r = await api('GET', '/api/me/schedule-feed');
            draw(r.ok && r.data.active, null);
        }
        function draw(active, url) {
            clear(container);
            container.appendChild(el('p', { text: 'A calendar link lets a calendar app show the schedules of the streams you follow, ' +
                'are interested in or own. It works without signing in, only for your own feed, and only reads.' }));
            if (url) {
                var field = el('input', { type: 'text', value: url, readonly: 'readonly', style: { width: '100%' } });
                container.appendChild(el('div', {}, [
                    el('div', { text: 'Your calendar link (shown once, copy it now):' }), field,
                    el('button', { type: 'button', class: 'btn btn-sm btn-secondary', text: 'Copy', on: { click: async function () {
                        try { await navigator.clipboard.writeText(url); toast('Copied', 'success'); } catch (e) { toast('Copy it by hand', 'error'); }
                    } } })
                ]));
            } else {
                container.appendChild(el('p', { text: active ? 'You have a calendar link. It cannot be shown again; regenerate it to get a new one.' : 'You have no calendar link.' }));
            }
            var make = el('button', { type: 'button', class: 'btn btn-sm btn-primary', text: active ? 'Regenerate' : 'Create link', on: { click: async function () {
                var r = await api('POST', '/api/me/schedule-feed');
                if (!r.ok) { toast(errorOf(r, 'Could not make the link'), 'error'); return; }
                draw(true, r.data.url);
            } } });
            container.appendChild(make);
            if (active) container.appendChild(el('button', { type: 'button', class: 'btn btn-sm btn-danger', text: 'Revoke', on: { click: async function () {
                var r = await api('DELETE', '/api/me/schedule-feed');
                if (r.ok) draw(false, null); else toast(errorOf(r, 'Could not revoke the link'), 'error');
            } } }));
            container.appendChild(el('p', { class: 'schedule-feed-warning', text: FEED_WARNING, style: { fontSize: '0.8125rem' } }));
        }
        await load();
    }

    window.StreamSchedule = {
        mountWatch: mountWatch, mountUpcoming: mountUpcoming, mountOwner: mountOwner, mountFeed: mountFeed,
        countdownText: countdownText, whenText: whenText, FEED_WARNING: FEED_WARNING
    };

    function autoMount() {
        var strip = document.getElementById('schedule-upcoming');
        if (strip) mountUpcoming(strip);
        var feed = document.getElementById('calendar-feed-settings');
        if (feed) mountFeed(feed);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', autoMount);
    else autoMount();
})();

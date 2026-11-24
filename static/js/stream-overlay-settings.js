/*
 * Chat overlay block of the stream settings (1.24.0): create, copy (shown once), regenerate and revoke the overlay
 * link of one stream, the instructions for an OBS browser source, and the link for an OBS custom dock.
 *
 *   StreamOverlaySettings.mount(el, streamId)
 *
 * Everything that came from the server goes in through textContent; nothing here assigns innerHTML and no inline
 * handler is made. Regenerate and Revoke ask first, on a row of their own: a confirm within CONFIRM_DELAY_MS of the
 * question appearing, or the second click of a double click, does nothing. Create, regenerate and revoke ignore a
 * click while a request is in flight.
 */
(function () {
    'use strict';

    var CONFIRM_DELAY_MS = 600;

    var BROADCAST_NOTE = 'Whatever the overlay shows is broadcast to everyone who can see your video. Chat messages ' +
        'that members post are put on your picture as they are, under the names viewers see (an anonymous post stays ' +
        'anonymous). Deleted and moderated messages disappear from it.';
    var PRIVATE_NOTE = 'This stream is not public. The overlay still works with your link, because you chose to put ' +
        'your own chat on your own broadcast, and so the chat is shown to everyone who can see the video, including ' +
        'people who cannot read the chat on the portal.';

    function el(tag, props, kids) {
        var n = document.createElement(tag);
        Object.keys(props || {}).forEach(function (k) {
            if (k === 'text') n.textContent = props[k];
            else if (k === 'class') n.className = props[k];
            else if (k === 'on') Object.keys(props.on).forEach(function (t) { n.addEventListener(t, props.on[t]); });
            else if (k === 'style') Object.keys(props.style).forEach(function (s) { n.style[s] = props.style[s]; });
            else if (k === 'value' || k === 'disabled' || k === 'type') n[k] = props[k];
            else n.setAttribute(k, props[k]);
        });
        (kids || []).forEach(function (c) { if (c) n.appendChild(c); });
        return n;
    }

    function toast(msg, kind) {
        if (window.Portal && typeof window.Portal.toast === 'function') window.Portal.toast(msg, kind);
    }

    async function api(method, url) {
        try {
            var resp = await fetch(url, { method: method, credentials: 'include', headers: { 'Accept': 'application/json' } });
            var data = null;
            try { data = await resp.json(); } catch (e) { data = null; }
            return { ok: resp.ok, status: resp.status, data: data || {} };
        } catch (e) {
            return { ok: false, status: 0, data: { error: 'Network error' } };
        }
    }

    function absolute(url) {
        if (typeof url !== 'string' || !url) return '';
        if (url.charAt(0) === '/') return (window.location && window.location.origin ? window.location.origin : '') + url;
        return url;
    }

    async function copy(text) {
        try { await navigator.clipboard.writeText(text); toast('Copied', 'success'); } catch (e) { toast('Copy it by hand', 'error'); }
    }

    async function mount(container, streamId) {
        if (!container) return;
        var base = '/api/streams/' + Number(streamId) + '/overlay';
        var status = { active: false, available: true, stream_public: true, max_sockets: 3, dock_url: '' };
        var shown = null, busy = false;

        async function load() {
            var r = await api('GET', base);
            if (r.ok) status = r.data;
            draw(null, false);
        }

        /* the address is shown once; it does not stay on the page when the settings dialog is closed */
        var modal = container.closest ? container.closest('.modal') : null;
        if (modal && typeof MutationObserver === 'function') {
            new MutationObserver(function () {
                if (shown !== null && modal.style.display === 'none') draw(null, false);
            }).observe(modal, { attributes: true, attributeFilter: ['style', 'class'] });
        }

        async function make() {
            if (busy) return;
            busy = true;
            var r = await api('POST', base);
            busy = false;
            if (!r.ok) { toast((r.data && r.data.error) || 'Could not make the link', 'error'); draw(shown, false); return; }
            status.active = true;
            status.stream_public = r.data.stream_public;
            draw(absolute(r.data.url), false);
        }

        async function revoke() {
            if (busy) return;
            busy = true;
            var r = await api('DELETE', base);
            busy = false;
            if (r.ok) { status.active = false; draw(null, false); }
            else { toast((r.data && r.data.error) || 'Could not revoke the link', 'error'); draw(shown, false); }
        }

        function draw(url, confirming) {
            shown = url || null;
            container.textContent = '';
            container.appendChild(el('p', { text: 'Show your stream chat on your picture with an OBS browser source. The link is read-only: ' +
                'it shows the chat of this stream and nothing else, and it works without signing in. One link is active at a time, and at most ' +
                Number(status.max_sockets || 3) + ' browser sources can use it at once. The link ends when your password is changed or reset, ' +
                'or when you are signed out everywhere; make a new link then and put it in OBS again.' }));
            container.appendChild(el('p', { class: 'overlay-broadcast-note', role: 'note', text: BROADCAST_NOTE }));
            if (status.stream_public === false) container.appendChild(el('p', { class: 'overlay-private-note', role: 'alert', text: PRIVATE_NOTE }));
            if (status.available === false) {
                container.appendChild(el('p', { text: 'This stream has no chat of its own, so there is no overlay for it.' }));
                return;
            }
            if (url) {
                var field = el('input', { type: 'text', value: url, readonly: 'readonly', 'aria-label': 'Your overlay link', style: { width: '100%' } });
                container.appendChild(el('div', {}, [
                    el('div', { text: 'Your overlay link (shown once, copy it now):' }), field,
                    el('button', { type: 'button', class: 'btn btn-sm btn-secondary', text: 'Copy', on: { click: function () { return copy(url); } } })
                ]));
                container.appendChild(el('ol', {}, [
                    el('li', { text: 'In OBS, add a Browser source and paste the link as its URL.' }),
                    el('li', { text: 'Set the width and height to the size of the area for the chat (for example 480 by 720). Leave "Use custom frame rate" off.' }),
                    el('li', { text: 'The page is transparent. To change the look, add options to the end of the link, after the token: &size=28 (letter size, 12 to 96), &lines=8 (most lines shown, 1 to 30), &fade=30 (seconds a line stays, 0 to 600; 0 keeps it until newer lines push it out).' }),
                    el('li', { text: 'The token is in the part of the link after the #, which is not sent to the portal when the page loads. Keep the whole link when you refresh or copy it.' })
                ]));
            } else {
                container.appendChild(el('p', { text: status.active
                    ? 'You have an overlay link. It cannot be shown again; regenerate it to get a new one.'
                    : 'You have no overlay link.' }));
            }
            if (confirming) {
                var revoking = confirming === 'revoke';
                container.appendChild(el('p', { class: 'overlay-confirm', role: 'alert', text: revoking
                    ? 'Revoking ends the link you have now. A browser source that uses it stops showing chat at once, and there is no link until you create a new one.'
                    : 'Regenerating ends the link you have now. A browser source that uses it stops showing chat at once until you give it the new link; replace the link in every source that has it.' }));
                var askedAt = Date.now();
                container.appendChild(el('button', { type: 'button', class: 'btn btn-sm btn-danger', text: revoking ? 'Yes, revoke' : 'Yes, regenerate', on: { click: function (e) {
                    if ((e && e.detail > 1) || Date.now() - askedAt < CONFIRM_DELAY_MS) return;
                    return revoking ? revoke() : make();
                } } }));
                container.appendChild(el('button', { type: 'button', class: 'btn btn-sm btn-secondary', text: 'Keep the current link', on: { click: function () { draw(url, false); } } }));
            } else {
                container.appendChild(el('button', { type: 'button', class: 'btn btn-sm btn-primary', text: status.active ? 'Regenerate' : 'Create link', on: { click: function () {
                    if (status.active) draw(url, 'regenerate'); else return make();
                } } }));
                if (status.active) container.appendChild(el('button', { type: 'button', class: 'btn btn-sm btn-danger', text: 'Revoke', on: { click: function () { draw(url, 'revoke'); } } }));
            }
            /* the dock: the compact watch chat behind the normal sign-in, no new credential */
            var dock = absolute(status.dock_url);
            if (dock) {
                container.appendChild(el('p', { style: { marginTop: '1rem' }, text: 'Chat dock for OBS: in OBS choose Docks, Custom Browser Docks, and add this address. ' +
                    'It is your normal chat window, so OBS shows the portal sign-in first. Sign in with your account there; the portal then opens the dashboard, so open the dock again (or reload it) to get the chat. No extra link or token is used.' }));
                container.appendChild(el('input', { type: 'text', value: dock, readonly: 'readonly', 'aria-label': 'Chat dock address', style: { width: '100%' } }));
                container.appendChild(el('button', { type: 'button', class: 'btn btn-sm btn-secondary', text: 'Copy dock address', on: { click: function () { return copy(dock); } } }));
            }
        }
        await load();
    }

    window.StreamOverlaySettings = { mount: mount, BROADCAST_NOTE: BROADCAST_NOTE, PRIVATE_NOTE: PRIVATE_NOTE };
})();

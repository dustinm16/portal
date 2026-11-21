/* Web Push for this browser: window.PortalPush.
 *
 *   PortalPush.supported()            true when this browser can do web push
 *   PortalPush.status()               Promise: {supported, enabled, permission, subscribed, devices}
 *   PortalPush.enable()               ask permission, register the worker, subscribe, tell the server
 *   PortalPush.disable()              remove this browser's subscription (server and browser)
 *   PortalPush.disableAll()           remove every device of the signed-in member
 *   PortalPush.mountSettings(el)      draw the "Phone notifications" block into el (user settings)
 *
 * Push is off (supported() is false) inside a frame, on a proxied page (/proxy/, /search/) and in the
 * embedded browser (/browser): nothing is registered or asked there.
 *
 * The worker (/sw.js) is registered with a scope nothing is served from, so it controls no page; push
 * and notification clicks work without that. Signing out removes this browser's device first when it
 * was enabled here. Nothing is ever subscribed without a call to enable() from a user action.
 */
(function () {
    'use strict';

    var SCOPE = '/push-sw/';
    var HINT = 'portal_push_on';

    function framed() {
        try {
            return window.top !== window.self;
        } catch (e) {
            return true;
        }
    }

    function onProxiedPath() {
        var path = window.location.pathname || '';
        return path.indexOf('/proxy/') === 0 || path === '/browser';
    }

    function inForeignContext() {
        var path = window.location.pathname || '';
        return framed() || onProxiedPath() || path.indexOf('/search/') === 0;
    }

    /* The sign-out hook, the device re-announcement and the tap relay need no permission prompt and no
       settings screen, so they also run where push cannot be switched on (/search/): only a framed page
       and a proxied page are left out. */
    function canAct() {
        return typeof navigator !== 'undefined' && 'serviceWorker' in navigator &&
            typeof window !== 'undefined' && 'PushManager' in window && !framed() && !onProxiedPath();
    }

    function hinted() {
        try {
            return localStorage.getItem(HINT) === '1';
        } catch (e) {
            return false;
        }
    }

    function supported() {
        return typeof navigator !== 'undefined' && 'serviceWorker' in navigator &&
            typeof window !== 'undefined' && 'PushManager' in window && 'Notification' in window &&
            !inForeignContext();
    }

    function isIOS() {
        var ua = navigator.userAgent || '';
        return /iPad|iPhone|iPod/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
    }

    function isStandalone() {
        return !!(navigator.standalone || (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches));
    }

    function api(method, url, body) {
        var opts = { method: method, credentials: 'same-origin', headers: {} };
        if (body !== undefined) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        return fetch(url, opts).then(function (r) {
            return r.json().catch(function () { return {}; }).then(function (data) {
                if (!r.ok) {
                    var err = new Error(data && data.error ? data.error : 'Request failed (' + r.status + ')');
                    err.status = r.status;
                    throw err;
                }
                return data;
            });
        });
    }

    function urlBase64ToUint8Array(text) {
        var pad = '='.repeat((4 - text.length % 4) % 4);
        var raw = atob((text + pad).replace(/-/g, '+').replace(/_/g, '/'));
        var out = new Uint8Array(raw.length);
        for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
        return out;
    }

    function waitActive(reg) {
        if (reg.active) return Promise.resolve(reg);
        var worker = reg.installing || reg.waiting;
        if (!worker) return Promise.reject(new Error('The worker did not install'));
        return new Promise(function (resolve, reject) {
            function settle() {
                if (worker.state === 'activated') resolve(reg);
                else if (worker.state === 'redundant') reject(new Error('The worker did not install'));
                else return false;
                return true;
            }
            worker.addEventListener('statechange', settle);
            settle();   /* it may have activated before the listener was attached */
        });
    }

    function currentRegistration() {
        return navigator.serviceWorker.getRegistration(SCOPE);
    }

    function currentSubscription() {
        return currentRegistration().then(function (reg) {
            return reg && reg.pushManager ? reg.pushManager.getSubscription() : null;
        });
    }

    /* A subscription made with another application server key (the superadmin reset the VAPID key since) can
       never receive a push again: it does not count as subscribed and enable() replaces it. A browser that does
       not show the key counts as a match. */
    function keyMatches(sub, publicKey) {
        var have = sub && sub.options && sub.options.applicationServerKey;
        if (!have || !publicKey) return true;
        var a = new Uint8Array(have), b = urlBase64ToUint8Array(publicKey);
        if (a.length !== b.length) return false;
        for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
        return true;
    }

    function status() {
        if (!supported()) {
            return Promise.resolve({ supported: false, enabled: false, permission: 'denied', subscribed: false, devices: 0 });
        }
        return Promise.all([api('GET', '/api/push/config'), currentSubscription(), api('GET', '/api/push/subscriptions')])
            .then(function (res) {
                return {
                    supported: true, enabled: !!res[0].enabled, permission: Notification.permission,
                    subscribed: !!res[1] && keyMatches(res[1], res[0].public_key), devices: (res[2].devices || []).length
                };
            });
    }

    function enable() {
        if (!supported()) return Promise.reject(new Error('This browser cannot receive push notifications'));
        var config;
        /* The permission prompt starts here, synchronously, inside the click that called enable(): some
           browsers (Safari) do not count it as a user gesture after an await. The config is fetched meanwhile. */
        var asked = Notification.requestPermission();
        return Promise.all([asked, api('GET', '/api/push/config')]).then(function (res) {
            config = res[1];
            if (res[0] !== 'granted') throw new Error('Notifications were not allowed in the browser');
            if (!config.enabled || !config.public_key) throw new Error('Push notifications are switched off on this server');
            return navigator.serviceWorker.register('/sw.js', { scope: SCOPE });
        }).then(waitActive).then(function (reg) {
            function fresh() {
                return reg.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: urlBase64ToUint8Array(config.public_key)
                });
            }
            return reg.pushManager.getSubscription().then(function (existing) {
                if (!existing) return fresh();
                if (keyMatches(existing, config.public_key)) return existing;
                return existing.unsubscribe().then(fresh, fresh);     // made with a key the server no longer has
            });
        }).then(function (sub) {
            return api('POST', '/api/push/subscriptions', sub.toJSON()).then(function () {
                try { localStorage.setItem(HINT, '1'); } catch (e) { /* private mode */ }
                return true;
            }, function (err) {
                /* The server did not take the device (another account holds it, push was switched off, a server
                   error): a browser subscription nobody can send to is undone, so the switch is honestly off. */
                forget();
                var undo = function () { throw err; };
                return Promise.resolve().then(function () { return sub.unsubscribe(); }).then(undo, undo);
            });
        });
    }

    function forget() {
        try { localStorage.removeItem(HINT); } catch (e) { /* private mode */ }
    }

    function disable() {
        if (!supported()) return Promise.resolve(false);
        return currentSubscription().then(function (sub) {
            forget();
            if (!sub) return false;
            return api('POST', '/api/push/unsubscribe', { endpoint: sub.endpoint })
                .catch(function () { /* the server drops it on the next failed push */ })
                .then(function () { return sub.unsubscribe(); });
        });
    }

    function disableAll() {
        return api('DELETE', '/api/push/subscriptions').then(function () { return disable(); });
    }

    /* Sign out: when this browser was enabled here, tell the server which device it is (POST /logout with
       the endpoint in the body, never in the URL), drop the browser's own subscription, then go to /logout
       (bounded wait). Without a push device here the link works as it always did. */
    document.addEventListener('click', function (ev) {
        var a = ev.target && ev.target.closest ? ev.target.closest('a[href="/logout"]') : null;
        if (!a || !hinted() || !canAct()) return;
        ev.preventDefault();
        var done = false;
        /* Always /logout, never /login: when the POST was slow or failed the link still signs the member out;
           when it worked the session is gone and /logout just redirects to the login page. */
        function go() { if (!done) { done = true; window.location.href = '/logout'; } }
        setTimeout(go, 2500);
        currentSubscription().then(function (sub) {
            forget();
            if (!sub) return fetch('/logout', { method: 'POST', credentials: 'same-origin' });
            return fetch('/logout', {
                method: 'POST', credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ endpoint: sub.endpoint })
            }).then(function () { return sub.unsubscribe(); });
        }).then(go, go);
    });

    /* Every page load where push is on for this browser: tell the server this device belongs to the session
       that is open now (the server only re-ties a device it already holds with the same keys). A device
       registered under a session that has since expired is thereby always tied to a live session, so signing
       out (here, or from the Sessions page) ends it. Silent: nothing is asked and nothing is shown. */
    function reannounce() {
        if (!hinted() || !canAct() || typeof Notification === 'undefined' || Notification.permission !== 'granted') return;
        currentSubscription().then(function (sub) {
            if (!sub) return null;
            var body = sub.toJSON();
            body.rebind = true;     /* refresh a device the server holds for this member; never register or take one */
            return api('POST', '/api/push/subscriptions', body).then(null, function (err) {
                if (!err || err.status !== 404) throw err;
                /* The server does not hold this device (it was removed, or it belonged to another member): this
                   browser is not subscribed as far as this member is concerned. */
                forget();
                return Promise.resolve().then(function () { return sub.unsubscribe(); }).then(null, function () { /* gone */ });
            });
        }).then(null, function () { /* signed out, or the server refused: nothing to do */ });
    }
    reannounce();

    /* A tap on a notification: the worker controls no page, so it cannot navigate one; it focuses a portal
       window and posts the target here. Only a relative path of this site is followed. */
    function relativeTarget(value) {
        if (typeof value !== 'string' || value.charAt(0) !== '/' || value.charAt(1) === '/' ||
            value.indexOf('\\') !== -1 || value.length > 300) return null;
        return value;
    }

    if (canAct() && navigator.serviceWorker.addEventListener) {
        navigator.serviceWorker.addEventListener('message', function (ev) {
            var d = ev && ev.data;
            if (!d || d.type !== 'portal-open') return;
            var url = relativeTarget(d.url);
            var here = (window.location.pathname || '') + (window.location.search || '') + (window.location.hash || '');
            if (url && url !== here) window.location.href = url;
            /* tell the worker this page took it, so it does not open another window */
            try { if (ev.ports && ev.ports[0]) ev.ports[0].postMessage('ok'); } catch (e) { /* gone */ }
        });
        if (navigator.serviceWorker.startMessages) navigator.serviceWorker.startMessages();
    }

    /* ---- the "Phone notifications" block of the user settings ---- */
    var KINDS = [
        ['dm', 'Direct messages'],
        ['mention', 'Mentions (not in channels you muted)'],
        ['golive', 'Streams you follow going live']
    ];

    function el(tag, text, cls) {
        var n = document.createElement(tag);
        if (text) n.textContent = text;
        if (cls) n.className = cls;
        return n;
    }

    function mountSettings(root) {
        if (!root) return;
        root.textContent = '';
        var note = el('p', '', 'push-note');
        note.style.cssText = 'color: var(--text-secondary); font-size: 0.8125rem; margin: 0 0 0.75rem;';
        root.appendChild(note);
        if (!supported()) {
            note.textContent = isIOS() && !isStandalone()
                ? 'On iPhone and iPad, push notifications work only from the installed app (iOS 16.4 or later): ' +
                  'open Share, choose Add to Home Screen, then open Portal from its icon and turn this on there.'
                : 'This browser or page cannot receive push notifications.';
            return;
        }
        note.textContent = 'A phone or browser notification for the things below, only while Portal is not open. ' +
            'It says that something happened, never what was written.';
        if (isIOS() && !isStandalone()) {
            var hint = el('p', 'Install hint: on iPhone and iPad this works only from the home-screen app (iOS 16.4 or later).');
            hint.style.cssText = 'color: var(--accent-yellow, #d29922); font-size: 0.8125rem; margin: 0 0 0.75rem;';
            root.appendChild(hint);
        }
        var row = el('label', '', 'push-switch');
        row.style.cssText = 'display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;';
        var sw = document.createElement('input');
        sw.type = 'checkbox';
        sw.id = 'push-enable-switch';
        row.appendChild(sw);
        row.appendChild(el('span', 'Notify me on this browser'));
        root.appendChild(row);
        var msg = el('p', '');
        msg.style.cssText = 'font-size: 0.8125rem; margin: 0 0 0.75rem; color: var(--text-muted);';
        root.appendChild(msg);
        var kinds = el('div', '');
        root.appendChild(kinds);
        var devices = el('div', '');
        root.appendChild(devices);

        function say(text, bad) {
            msg.textContent = text || '';
            msg.style.color = bad ? 'var(--accent-red, #f85149)' : 'var(--text-muted)';
        }

        function drawKinds(prefs) {
            kinds.textContent = '';
            KINDS.forEach(function (k) {
                var l = el('label', '');
                l.style.cssText = 'display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;';
                var c = document.createElement('input');
                c.type = 'checkbox';
                c.checked = prefs[k[0]] !== false;
                c.addEventListener('change', function () {
                    var body = {};
                    body[k[0]] = c.checked;
                    api('PUT', '/api/push/prefs', body).catch(function (e) {
                        c.checked = !c.checked;
                        say(e.message, true);
                    });
                });
                l.appendChild(c);
                l.appendChild(el('span', k[1]));
                kinds.appendChild(l);
            });
        }

        function drawDevices(list) {
            devices.textContent = '';
            if (!list.length) return;
            devices.appendChild(el('h5', 'Your devices')).style.cssText = 'margin: 0.75rem 0 0.25rem;';
            list.forEach(function (d) {
                var r = el('div', '');
                r.style.cssText = 'display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; margin-bottom: 0.25rem;';
                var label = String(d.label || 'Device') + (d.this_session ? ' (this session)' : '');
                r.appendChild(el('span', label));
                var b = el('button', 'Remove', 'btn btn-secondary btn-sm');
                b.type = 'button';
                b.addEventListener('click', function () {
                    b.disabled = true;
                    api('DELETE', '/api/push/subscriptions/' + encodeURIComponent(d.id)).then(refresh, function (e) {
                        b.disabled = false;
                        say(e.message, true);
                    });
                });
                r.appendChild(b);
                devices.appendChild(r);
            });
        }

        function refresh(keepMessage) {
            return Promise.all([status(), api('GET', '/api/push/prefs'), api('GET', '/api/push/subscriptions')])
                .then(function (res) {
                    var st = res[0];
                    sw.checked = !!(st.subscribed && st.permission === 'granted');
                    sw.disabled = !st.enabled;
                    if (!st.enabled) say('Push notifications are switched off on this server.');
                    else if (st.permission === 'denied') say('Notifications are blocked for this site in the browser settings.', true);
                    else if (!keepMessage) say('');
                    drawKinds(res[1].prefs || {});
                    drawDevices(res[2].devices || []);
                }).catch(function (e) { say(e.message, true); });
        }

        sw.addEventListener('change', function () {
            var want = sw.checked;
            sw.disabled = true;
            /* the permission prompt is asked inside this click handler: a user gesture */
            var failed = false;
            (want ? enable() : disable()).then(function () { say(''); }, function (e) {
                failed = true;
                say(e.message, true);
            }).then(function () { sw.disabled = false; return refresh(failed); });
        });
        refresh();
    }

    window.PortalPush = { supported: supported, status: status, enable: enable, disable: disable, disableAll: disableAll,
                          mountSettings: mountSettings };
})();

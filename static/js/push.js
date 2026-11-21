/* Web Push for this browser: window.PortalPush.
 *
 *   PortalPush.supported()            true when this browser can do web push
 *   PortalPush.status()               Promise: {supported, enabled, permission, subscribed, devices}
 *   PortalPush.enable()               ask permission, register the worker, subscribe, tell the server
 *   PortalPush.disable()              remove this browser's subscription (server and browser)
 *   PortalPush.disableAll()           remove every device of the signed-in member
 *
 * The worker (/sw.js) is registered with a scope nothing is served from, so it controls no page; push
 * and notification clicks work without that. Signing out removes this browser's device first when it
 * was enabled here. Nothing is ever subscribed without a call to enable() from a user action.
 */
(function () {
    'use strict';

    var SCOPE = '/push-sw/';
    var HINT = 'portal_push_on';

    function supported() {
        return typeof navigator !== 'undefined' && 'serviceWorker' in navigator &&
            typeof window !== 'undefined' && 'PushManager' in window && 'Notification' in window;
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
            worker.addEventListener('statechange', function () {
                if (worker.state === 'activated') resolve(reg);
                else if (worker.state === 'redundant') reject(new Error('The worker did not install'));
            });
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

    function status() {
        if (!supported()) {
            return Promise.resolve({ supported: false, enabled: false, permission: 'denied', subscribed: false, devices: 0 });
        }
        return Promise.all([api('GET', '/api/push/config'), currentSubscription(), api('GET', '/api/push/subscriptions')])
            .then(function (res) {
                return {
                    supported: true, enabled: !!res[0].enabled, permission: Notification.permission,
                    subscribed: !!res[1], devices: (res[2].devices || []).length
                };
            });
    }

    function enable() {
        if (!supported()) return Promise.reject(new Error('This browser cannot receive push notifications'));
        var config;
        return api('GET', '/api/push/config').then(function (c) {
            config = c;
            if (!c.enabled || !c.public_key) throw new Error('Push notifications are switched off on this server');
            return Notification.requestPermission();
        }).then(function (permission) {
            if (permission !== 'granted') throw new Error('Notifications were not allowed in the browser');
            return navigator.serviceWorker.register('/sw.js', { scope: SCOPE });
        }).then(waitActive).then(function (reg) {
            return reg.pushManager.getSubscription().then(function (existing) {
                return existing || reg.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: urlBase64ToUint8Array(config.public_key)
                });
            });
        }).then(function (sub) {
            return api('POST', '/api/push/subscriptions', sub.toJSON()).then(function () {
                try { localStorage.setItem(HINT, '1'); } catch (e) { /* private mode */ }
                return true;
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

    /* Sign out: when this browser was enabled here, remove its device first (bounded wait). */
    document.addEventListener('click', function (ev) {
        var a = ev.target && ev.target.closest ? ev.target.closest('a[href="/logout"]') : null;
        var on = false;
        try { on = localStorage.getItem(HINT) === '1'; } catch (e) { on = false; }
        if (!a || !on || !supported()) return;
        ev.preventDefault();
        var done = false;
        function go() { if (!done) { done = true; window.location.href = '/logout'; } }
        setTimeout(go, 1500);
        disable().then(go, go);
    });

    window.PortalPush = { supported: supported, status: status, enable: enable, disable: disable, disableAll: disableAll };
})();

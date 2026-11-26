/* Portal push worker. It handles push messages and notification clicks and nothing else:
   no network interception, no cache storage, no page is ever controlled by it (it is registered with a
   scope nothing is served from). The message is a small JSON object: type, title, body and
   a relative URL; anything else in it is ignored. */
'use strict';

function cleanText(value, limit) {
    return typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, limit) : '';
}

/* A same-origin relative path, or "/" when the value is anything else. The path part may hold no dot
   segment (plain or percent-encoded) and no encoded slash or backslash, and the URL as the browser
   resolves it must stay on this origin with a path that does not start with "//". */
function safeUrl(value) {
    if (typeof value !== 'string' || value.charAt(0) !== '/' || value.charAt(1) === '/' ||
        value.indexOf('\\') !== -1 || value.length > 300) {
        return '/';
    }
    var path = value.split(/[?#]/)[0];
    if (/%(2f|5c)/i.test(path)) return '/';
    var segments = path.split('/');
    for (var i = 0; i < segments.length; i++) {
        var seg = segments[i].toLowerCase().split('%2e').join('.');
        if (seg === '.' || seg === '..') return '/';
    }
    try {
        var u = new URL(value, self.location.origin);
        if (u.origin !== self.location.origin || u.pathname.charAt(0) !== '/' || u.pathname.indexOf('//') === 0) {
            return '/';
        }
        return u.pathname + u.search + u.hash;
    } catch (e) {
        return '/';
    }
}

self.addEventListener('push', function (event) {
    var data = {};
    try {
        data = event.data ? event.data.json() : {};
    } catch (e) {
        data = {};
    }
    if (!data || typeof data !== 'object') data = {};
    var title = cleanText(data.title, 100) || 'Portal';
    var options = {
        body: cleanText(data.body, 200),
        icon: '/static/icons/icon-192.png',
        badge: '/static/icons/badge-96.png',
        data: { url: safeUrl(data.url) }
    };
    var tag = cleanText(data.tag, 40);
    if (tag) options.tag = tag;
    /* Always show something: a push that shows nothing can get the subscription revoked. */
    event.waitUntil(self.registration.showNotification(title, options));
});

/* Where a tap may land: a top-level window of this site that is not a proxied page or the embedded browser
   (those are somebody else's content in a portal frame, or the shell around it). */
function portalWindow(c) {
    try {
        var u = new URL(c.url);
        if (u.origin !== self.location.origin) return false;
        if (c.frameType && c.frameType !== 'top-level') return false;
        return u.pathname.indexOf('/proxy/') !== 0 && u.pathname !== '/browser' && u.pathname !== '/rbrowser';
    } catch (e) {
        return false;
    }
}

/* This worker controls no page (by design), so WindowClient.navigate() is refused for it. The fallback asks
   the page itself to go there (push.js listens for it) and waits a moment for its answer on a private
   channel: a portal page without that script never answers, and the next window or a new one is used. */
function relay(client, target) {
    return new Promise(function (resolve) {
        var timer = setTimeout(function () { resolve(false); }, 800);
        try {
            var channel = new MessageChannel();
            channel.port1.onmessage = function () { clearTimeout(timer); resolve(true); };
            client.postMessage({ type: 'portal-open', url: target }, [channel.port2]);
        } catch (e) {
            clearTimeout(timer);
            resolve(false);
        }
    });
}

function bringTo(client, absolute, target) {
    return Promise.resolve(client.focus ? client.focus() : null).then(function (focused) {
        var win = focused || client;
        return win.navigate(absolute).then(function () { return true; });
    }).then(null, function () {
        return relay(client, target);
    });
}

self.addEventListener('notificationclick', function (event) {
    event.notification.close();
    var target = safeUrl(event.notification.data && event.notification.data.url);
    var absolute = new URL(target, self.location.origin).href;
    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (list) {
            var windows = list.filter(portalWindow);
            for (var i = 0; i < windows.length; i++) {
                if (windows[i].url === absolute && 'focus' in windows[i]) return windows[i].focus();
            }
            /* an open portal window goes to the page; the one in front first */
            windows.sort(function (a, b) { return (b.focused ? 1 : 0) - (a.focused ? 1 : 0); });
            var chain = Promise.resolve(false);
            windows.forEach(function (c) {
                chain = chain.then(function (done) { return done ? true : bringTo(c, absolute, target); });
            });
            return chain.then(function (done) {
                return done ? null : self.clients.openWindow(absolute);
            });
        })
    );
});

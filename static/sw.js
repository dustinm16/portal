/* Portal push worker. It handles push messages and notification clicks and nothing else:
   no network interception, no cache storage, no page is ever controlled by it (it is registered with a
   scope nothing is served from). The message is a small JSON object: type, title, body and
   a relative URL; anything else in it is ignored. */
'use strict';

function cleanText(value, limit) {
    return typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, limit) : '';
}

/* A same-origin relative path, or "/" when the value is anything else. */
function safeUrl(value) {
    if (typeof value !== 'string' || value.charAt(0) !== '/' || value.charAt(1) === '/' ||
        value.indexOf('\\') !== -1 || value.length > 300) {
        return '/';
    }
    try {
        var u = new URL(value, self.location.origin);
        if (u.origin !== self.location.origin) return '/';
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

self.addEventListener('notificationclick', function (event) {
    event.notification.close();
    var target = safeUrl(event.notification.data && event.notification.data.url);
    var absolute = new URL(target, self.location.origin).href;
    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (list) {
            for (var i = 0; i < list.length; i++) {
                var c = list[i];
                var same = false;
                try { same = new URL(c.url).origin === self.location.origin; } catch (e) { same = false; }
                if (same && c.url === absolute && 'focus' in c) return c.focus();
            }
            return self.clients.openWindow(absolute);
        })
    );
});

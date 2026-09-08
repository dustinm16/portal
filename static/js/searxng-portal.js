/**
 * Open Relay Portal <-> SearXNG integration.
 *
 * Injected by http_searxng_proxy into every SearXNG HTML page (with theme.js,
 * portal.css and searxng-portal.css). It:
 *   - strips SearXNG's own `theme-*` <html> class (portal theme drives colors)
 *   - prepends the full portal navbar so /search/ reads as a portal service
 *   - mounts the shared ThemeSwitcher (from theme.js) on that navbar
 *
 * Runs deferred; theme.js has already applied the portal theme pre-paint.
 */
(function () {
    'use strict';

    // SearXNG's <html class="... theme-auto ..."> would otherwise define its own
    // --color-* palette at higher specificity than searxng-portal.css's :root.
    var root = document.documentElement;
    root.className = root.className.replace(/\btheme-(auto|dark|light|black)\b/g, ' ').replace(/\s+/g, ' ').trim();

    // Are we running inside the portal's embedded browser (an <iframe>)? If so,
    // skip the portal navbar (the embedded browser has its own chrome) and make
    // external result links open in a real top-level tab — the embedded browser
    // can only proxy its own connection target, not arbitrary sites.
    var FRAMED = false;
    try { FRAMED = window.self !== window.top; } catch (e) { FRAMED = true; }

    var NAV_LINKS = [
        { href: '/search/', label: 'Search' },
        { href: '/search/preferences', label: 'Preferences' },
        { href: '/chat', label: 'Chat' },
        { href: '/streams', label: 'Streams' },
        { href: '/docs', label: 'API Docs' },
        { href: '/about', label: 'About' },
        { href: '/guides', label: 'Guides' },
    ];

    var BRAND_SVG = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">' +
        '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/></svg>';
    var TOGGLE_SVG = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg>';
    var TERM_SVG = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="20" height="20"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>';
    var USER_SVG = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="18" height="18"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>';

    function buildNavbar() {
        var nav = document.createElement('nav');
        nav.className = 'navbar portal-searxng-nav';

        var here = location.pathname.replace(/\/+$/, '') || '/';
        var links = NAV_LINKS.map(function (l) {
            var active = (l.href.replace(/\/+$/, '') || '/') === here ? ' aria-current="page"' : '';
            return '<a href="' + l.href + '"' + active + '>' + l.label + '</a>';
        }).join('');

        nav.innerHTML =
            '<a class="navbar-brand" href="/dashboard" style="text-decoration:none">' + BRAND_SVG + 'Open Relay Portal</a>' +
            '<button class="navbar-toggle" aria-label="Toggle menu" aria-expanded="false">' + TOGGLE_SVG + '</button>' +
            '<div class="navbar-menu">' +
                links +
                '<a href="/terminal/local" class="navbar-terminal" title="Open Terminal" id="sx-terminal-btn" style="display:none">' + TERM_SVG + '</a>' +
                '<a href="/dashboard" class="navbar-user" title="User Settings">' + USER_SVG +
                    '<span id="sx-username"></span>' +
                    '<span id="sx-admin-badge" class="admin-badge" style="display:none">Admin</span>' +
                '</a>' +
                '<a href="/logout">Logout</a>' +
            '</div>';

        document.body.insertBefore(nav, document.body.firstChild);

        var toggle = nav.querySelector('.navbar-toggle');
        var menu = nav.querySelector('.navbar-menu');
        toggle.addEventListener('click', function (e) {
            e.stopPropagation();
            menu.classList.toggle('open');
            toggle.setAttribute('aria-expanded', menu.classList.contains('open'));
        });
        document.addEventListener('click', function (e) {
            if (!menu.contains(e.target) && !toggle.contains(e.target)) {
                menu.classList.remove('open');
                toggle.setAttribute('aria-expanded', 'false');
            }
        });

        return nav;
    }

    function fillIdentity() {
        fetch('/api/me', { credentials: 'same-origin', headers: { Accept: 'application/json' } })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (me) {
                if (!me) return;
                var u = document.getElementById('sx-username');
                if (u && me.username) u.textContent = me.username;
                if (me.is_admin) {
                    var b = document.getElementById('sx-admin-badge');
                    if (b) { b.style.display = ''; b.textContent = me.role === 'superadmin' ? 'Super Admin' : 'Admin'; }
                    var t = document.getElementById('sx-terminal-btn');
                    if (t) t.style.display = '';
                }
            })
            .catch(function () {});
    }

    // Handle clicks on external result links while running inside the portal's
    // embedded browser. If that browser is in browser_mode it can proxy any
    // site, so open the result in a new *embedded* tab (through its proxy).
    // Otherwise it's confined to one origin and can't show the result at all —
    // open it in a real top-level tab.
    function enableFramedLinkEscape() {
        var peb = null;
        try {
            if (window.parent && window.parent !== window) {
                peb = window.parent.PORTAL_EMBEDDED_BROWSER || null;
            }
        } catch (e) { /* cross-origin parent — treat as confined */ }

        document.addEventListener('click', function (e) {
            var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
            if (!a) return;
            var u;
            try { u = new URL(a.href, location.href); } catch (err) { return; }
            if (!/^https?:$/.test(u.protocol) || u.origin === location.origin) return;

            if (peb && peb.browserMode && peb.proxyBase) {
                // Open in a new tab inside the embedded browser, via its proxy.
                e.preventDefault();
                var proxied = peb.proxyBase + '/' + u.href;
                try {
                    window.parent.postMessage({ type: 'openTab', url: proxied }, location.origin);
                } catch (err2) {
                    window.top.location.href = proxied;
                }
            } else {
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
            }
        }, true);
    }

    function start() {
        if (FRAMED) {
            enableFramedLinkEscape();
        } else {
            buildNavbar();
            fillIdentity();
        }
        if (window.ThemeSwitcher) window.ThemeSwitcher.init();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
}());

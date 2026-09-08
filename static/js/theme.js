/**
 * Open Relay Portal - Theme system (single source of truth)
 *
 * Load this in <head>, BEFORE portal.js and before first paint, on every page.
 * It: (1) applies the saved theme synchronously to avoid a flash, (2) exposes
 * `ThemeSwitcher` (used by portal.js and searxng-portal.js), (3) keeps the theme
 * in sync across tabs via the `storage` event.
 *
 * Theme id is stored in localStorage['portal-theme']; 'dark' is the default and
 * carries no attribute, every other id sets html[data-theme="<id>"].
 * The per-theme CSS variables live in static/css/portal.css.
 */
(function () {
    'use strict';

    var STORAGE_KEY = 'portal-theme';

    var THEMES = [
        { id: 'dark',          label: 'Dark',     swatch: 'linear-gradient(135deg,#1a1a2e 55%,#60a5fa 100%)' },
        { id: 'black',         label: 'Black',    swatch: 'linear-gradient(135deg,#000 55%,#3b82f6 100%)' },
        { id: 'grey',          label: 'Grey',     swatch: 'linear-gradient(135deg,#242424 55%,#9ca3af 100%)' },
        { id: 'slate',         label: 'Slate',    swatch: 'linear-gradient(135deg,#0f172a 55%,#7dd3fc 100%)' },
        { id: 'light',         label: 'Light',    swatch: 'linear-gradient(135deg,#f0f4f8 55%,#2563eb 100%)' },
        { id: 'blue',          label: 'Blue',     swatch: 'linear-gradient(135deg,#080f1a 55%,#3b82f6 100%)' },
        { id: 'green',         label: 'Green',    swatch: 'linear-gradient(135deg,#071a07 55%,#4ade80 100%)' },
        { id: 'red',           label: 'Red',      swatch: 'linear-gradient(135deg,#1a0505 55%,#f87171 100%)' },
        { id: 'orange',        label: 'Orange',   swatch: 'linear-gradient(135deg,#1a1005 55%,#fb923c 100%)' },
        { id: 'high-contrast', label: 'Hi-Con',   swatch: 'linear-gradient(135deg,#000 40%,#ffff00 100%)' },
    ];

    function readTheme() {
        try { return localStorage.getItem(STORAGE_KEY) || 'dark'; }
        catch (e) { return 'dark'; }
    }

    function applyThemeValue(name) {
        if (!name || name === 'dark') {
            document.documentElement.removeAttribute('data-theme');
        } else {
            document.documentElement.setAttribute('data-theme', name);
        }
    }

    // (1) Pre-paint: apply immediately, at script-eval time.
    applyThemeValue(readTheme());

    var ThemeSwitcher = {
        THEMES: THEMES,
        _dropdown: null,
        _wrap: null,

        current: readTheme,

        apply: function (name) {
            applyThemeValue(name);
            try { localStorage.setItem(STORAGE_KEY, name); } catch (e) {}
            this._updateSwatches();
        },

        /**
         * Mount the switcher button + swatch dropdown.
         * Anchor priority: an element with [data-theme-mount] (button appended
         * into it), else .navbar-user (button inserted before it). If neither is
         * present the theme is still applied, just without a control.
         */
        init: function () {
            applyThemeValue(this.current());

            var mount = document.querySelector('[data-theme-mount]');
            var userLink = document.querySelector('.navbar-user');
            if (!mount && !userLink) return;
            if (this._wrap) return; // already initialised

            var self = this;

            var wrap = document.createElement('div');
            wrap.className = 'navbar-theme-wrap';
            this._wrap = wrap;

            var btn = document.createElement('button');
            btn.className = 'navbar-theme-btn';
            btn.type = 'button';
            btn.title = 'Switch theme';
            btn.setAttribute('aria-label', 'Switch theme');
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor">' +
                '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" ' +
                'd="M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zm0 0h12a2 2 0 002-2v-4a2 2 0 00-2-2h-2.343M11 7.343l1.657-1.657a2 2 0 012.828 0l2.829 2.829a2 2 0 010 2.828l-8.486 8.485M7 17h.01"/></svg>';
            wrap.appendChild(btn);

            var dropdown = document.createElement('div');
            dropdown.className = 'theme-picker-dropdown';
            this._dropdown = dropdown;
            THEMES.forEach(function (t) {
                var swatch = document.createElement('div');
                swatch.className = 'theme-swatch' + (t.id === self.current() ? ' active' : '');
                swatch.dataset.themeId = t.id;
                swatch.innerHTML =
                    '<div class="theme-swatch-circle" style="background:' + t.swatch + '"></div>' +
                    '<span class="theme-swatch-label">' + t.label + '</span>';
                swatch.addEventListener('click', function () {
                    self.apply(t.id);
                    dropdown.classList.remove('open');
                });
                dropdown.appendChild(swatch);
            });
            document.body.appendChild(dropdown);

            btn.addEventListener('click', function (e) {
                e.stopPropagation();
                if (!dropdown.classList.contains('open')) {
                    var rect = btn.getBoundingClientRect();
                    dropdown.style.top = (rect.bottom + 4) + 'px';
                    dropdown.style.right = (window.innerWidth - rect.right) + 'px';
                }
                dropdown.classList.toggle('open');
            });
            document.addEventListener('click', function (e) {
                if (!wrap.contains(e.target) && !dropdown.contains(e.target)) {
                    dropdown.classList.remove('open');
                }
            });

            if (mount) {
                mount.appendChild(wrap);
            } else {
                userLink.parentNode.insertBefore(wrap, userLink);
            }
        },

        _updateSwatches: function () {
            if (!this._dropdown) return;
            var cur = this.current();
            this._dropdown.querySelectorAll('.theme-swatch').forEach(function (s) {
                s.classList.toggle('active', s.dataset.themeId === cur);
            });
        },
    };

    // (3) Cross-tab / cross-page sync.
    window.addEventListener('storage', function (e) {
        if (e.key === STORAGE_KEY) {
            applyThemeValue(e.newValue);
            ThemeSwitcher._updateSwatches();
        }
    });

    window.ThemeSwitcher = ThemeSwitcher;
    window.PORTAL_THEMES = THEMES;
}());

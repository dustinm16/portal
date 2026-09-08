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
 * Light-mode themes additionally set html[data-theme-mode="light"] so the CSS
 * can share the handful of "black overlay -> dark-on-light" tweaks.
 * The per-theme CSS variables live in static/css/portal.css.
 */
(function () {
    'use strict';

    var STORAGE_KEY = 'portal-theme';

    // mode: 'light' flips a few element-level overlays in portal.css (and the
    // SearXNG bridge) to dark-on-light. Everything else is driven by the CSS
    // custom properties in the html[data-theme="<id>"] blocks.
    var THEMES = [
        { id: 'dark',            label: 'Dark',     swatch: 'linear-gradient(135deg,#1a1a2e 55%,#60a5fa 100%)' },
        { id: 'black',           label: 'Black',    swatch: 'linear-gradient(135deg,#000 55%,#3b82f6 100%)' },
        { id: 'grey',            label: 'Grey',     swatch: 'linear-gradient(135deg,#242424 55%,#9ca3af 100%)' },
        { id: 'slate',           label: 'Slate',    swatch: 'linear-gradient(135deg,#0f172a 55%,#7dd3fc 100%)' },
        { id: 'blue',            label: 'Blue',     swatch: 'linear-gradient(135deg,#080f1a 55%,#3b82f6 100%)' },
        { id: 'purple',          label: 'Purple',   swatch: 'linear-gradient(135deg,#12081c 55%,#a78bfa 100%)' },
        { id: 'cyan',            label: 'Cyan',     swatch: 'linear-gradient(135deg,#04161a 55%,#22d3ee 100%)' },
        { id: 'green',           label: 'Green',    swatch: 'linear-gradient(135deg,#071a07 55%,#4ade80 100%)' },
        { id: 'red',             label: 'Red',      swatch: 'linear-gradient(135deg,#1a0505 55%,#f87171 100%)' },
        { id: 'rose',            label: 'Rose',     swatch: 'linear-gradient(135deg,#1a0510 55%,#fb7185 100%)' },
        { id: 'orange',          label: 'Orange',   swatch: 'linear-gradient(135deg,#1a1005 55%,#fb923c 100%)' },
        { id: 'amber',           label: 'Amber',    swatch: 'linear-gradient(135deg,#171205 55%,#f59e0b 100%)' },
        { id: 'nord',            label: 'Nord',     swatch: 'linear-gradient(135deg,#2e3440 55%,#88c0d0 100%)' },
        { id: 'dracula',         label: 'Dracula',  swatch: 'linear-gradient(135deg,#282a36 55%,#bd93f9 100%)' },
        { id: 'solarized-dark',  label: 'Sol Dark', swatch: 'linear-gradient(135deg,#002b36 55%,#268bd8 100%)' },
        { id: 'gruvbox',         label: 'Gruvbox',  swatch: 'linear-gradient(135deg,#282828 55%,#fabd2f 100%)' },
        { id: 'tokyo-night',     label: 'Tokyo',    swatch: 'linear-gradient(135deg,#1a1b26 55%,#7aa2f7 100%)' },
        { id: 'light',           label: 'Light',    swatch: 'linear-gradient(135deg,#f0f4f8 55%,#2563eb 100%)', mode: 'light' },
        { id: 'solarized-light', label: 'Sol Lt',   swatch: 'linear-gradient(135deg,#fdf6e3 55%,#268bd8 100%)', mode: 'light' },
        { id: 'sepia',           label: 'Sepia',    swatch: 'linear-gradient(135deg,#f4ecd9 55%,#9a6b3f 100%)', mode: 'light' },
        { id: 'nord-light',      label: 'Nord Lt',  swatch: 'linear-gradient(135deg,#eceff4 55%,#5e81ac 100%)', mode: 'light' },
        { id: 'synthwave',       label: 'Synth',    swatch: 'linear-gradient(135deg,#1b1035 40%,#ff2e97 100%)' },
        { id: 'matrix',          label: 'Matrix',   swatch: 'linear-gradient(135deg,#000 55%,#00ff41 100%)' },
        { id: 'cyberpunk',       label: 'Cyber',    swatch: 'linear-gradient(135deg,#0a0a02 45%,#00f0ff 100%)' },
        { id: 'high-contrast',   label: 'Hi-Con',   swatch: 'linear-gradient(135deg,#000 40%,#ffff00 100%)' },
        { id: 'aurora',          label: 'Aurora',   swatch: 'linear-gradient(135deg,#0e3a4a 0%,#1a2b5c 50%,#2d1b4e 100%)' },
        { id: 'nebula',          label: 'Nebula',   swatch: 'linear-gradient(135deg,#1e1145 0%,#7d2a8f 55%,#24215e 100%)' },
        { id: 'ember',           label: 'Ember',    swatch: 'linear-gradient(135deg,#1a0d05 30%,#fb923c 100%)' },
    ];

    var LIGHT_IDS = THEMES.filter(function (t) { return t.mode === 'light'; })
                          .map(function (t) { return t.id; });

    function readTheme() {
        try { return localStorage.getItem(STORAGE_KEY) || 'dark'; }
        catch (e) { return 'dark'; }
    }

    function applyThemeValue(name) {
        var root = document.documentElement;
        if (!name || name === 'dark') {
            root.removeAttribute('data-theme');
        } else {
            root.setAttribute('data-theme', name);
        }
        if (LIGHT_IDS.indexOf(name) !== -1) {
            root.setAttribute('data-theme-mode', 'light');
        } else {
            root.removeAttribute('data-theme-mode');
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
                var willOpen = !dropdown.classList.contains('open');
                dropdown.classList.toggle('open');
                if (willOpen) self._position(btn, dropdown);
            });
            window.addEventListener('resize', function () {
                if (dropdown.classList.contains('open')) self._position(btn, dropdown);
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

        // Anchor the (already-visible) dropdown to the button, keeping it on
        // screen. With ~28 themes it can be taller than the gap below the
        // button, so fall back to opening upward, then to pinning at the top
        // (max-height + scroll in the CSS takes it from there).
        _position: function (btn, dropdown) {
            var rect = btn.getBoundingClientRect();
            var margin = 8;
            dropdown.style.right = (window.innerWidth - rect.right) + 'px';
            var dh = dropdown.offsetHeight;
            if (rect.bottom + 4 + dh <= window.innerHeight - margin) {
                dropdown.style.top = (rect.bottom + 4) + 'px';
            } else if (rect.top - 4 - dh >= margin) {
                dropdown.style.top = (rect.top - 4 - dh) + 'px';
            } else {
                dropdown.style.top = margin + 'px';
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

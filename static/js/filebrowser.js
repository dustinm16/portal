/**
 * Open Relay Portal - shared file-browser UI pieces
 *
 * Used by the game-server jailed file browser (admin.html inline script +
 * dashboard.js, shared #gs-config-modal) and the admin file manager
 * (admin.html "Files" tab). Icons, formatters, a small context-menu
 * component, and a sortable-header helper — not a full framework, since
 * the two browsers have genuinely different data (the admin file manager
 * has owner/permissions; the jailed browser has a `writable` flag and no
 * OS metadata) and different endpoints. Keeping this file dependency-free
 * (no build step) so it can be dropped into any page with a plain
 * <script src> tag.
 */
const FileBrowser = (() => {
    // Small inline icons — no emoji, theme-colored via currentColor.
    const ICON_DIR = '<svg width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" style="flex-shrink:0;opacity:.7;"><path d="M2.5 5.5a1 1 0 0 1 1-1h4l1.4 1.6h7.6a1 1 0 0 1 1 1v8.4a1 1 0 0 1-1 1h-13a1 1 0 0 1-1-1V5.5z"/></svg>';
    const ICON_FILE = '<svg width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" style="flex-shrink:0;opacity:.55;"><path d="M5 2.5h6l4 4v10a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-13a1 1 0 0 1 1-1z"/><path d="M11 2.5v4h4"/></svg>';
    const ICON_SYMLINK = '<svg width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" style="flex-shrink:0;opacity:.55;"><path d="M8 12l4-4"/><path d="M9 5H6a3 3 0 0 0-3 3v0a3 3 0 0 0 3 3h1"/><path d="M11 15h3a3 3 0 0 0 3-3v0a3 3 0 0 0-3-3h-1"/></svg>';
    // Sort-direction chevrons for clickable column headers.
    const ICON_SORT_ASC = '<svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor" style="flex-shrink:0;"><path d="M5 2l4 5H1z"/></svg>';
    const ICON_SORT_DESC = '<svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor" style="flex-shrink:0;"><path d="M5 8L1 3h8z"/></svg>';

    function fmtBytes(n) {
        if (!n) return '0 B';
        const u = ['B', 'KB', 'MB', 'GB']; let i = 0;
        while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
        return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
    }

    function fmtMtime(ts) {
        if (!ts) return '';
        try { return new Date(ts * 1000).toLocaleString(); } catch (e) { return ''; }
    }

    /** Sort a list of {name, type, ...} entries: directories first, then by
     * `key` ('name' | 'size' | 'mtime'), `dir` is 1 (asc) or -1 (desc). */
    function sortEntries(entries, key, dir) {
        const list = (entries || []).slice();
        list.sort((a, b) => {
            if ((a.type === 'directory') !== (b.type === 'directory')) {
                return a.type === 'directory' ? -1 : 1;
            }
            let av = a[key], bv = b[key];
            if (key === 'name') { av = (av || '').toLowerCase(); bv = (bv || '').toLowerCase(); }
            else { av = av || 0; bv = bv || 0; }
            if (av < bv) return -1 * dir;
            if (av > bv) return 1 * dir;
            return a.name.localeCompare(b.name);
        });
        return list;
    }

    /** Wire click handlers onto column-header elements (data-sort-key="name|size|mtime")
     * inside `headEl`. `state` is a {key, dir} object mutated in place; `onChange` is
     * called (no args) after a header click so the caller can re-render. */
    function initSortableHeader(headEl, state, onChange) {
        if (!headEl || headEl.dataset.sortInit) return;
        headEl.dataset.sortInit = '1';
        headEl.querySelectorAll('[data-sort-key]').forEach(col => {
            col.style.cursor = 'pointer';
            col.style.userSelect = 'none';
            col.addEventListener('click', () => {
                const key = col.dataset.sortKey;
                if (state.key === key) state.dir *= -1;
                else { state.key = key; state.dir = 1; }
                renderSortIndicators(headEl, state);
                onChange();
            });
        });
        renderSortIndicators(headEl, state);
    }

    function renderSortIndicators(headEl, state) {
        headEl.querySelectorAll('[data-sort-key]').forEach(col => {
            const label = col.dataset.label || col.textContent.trim();
            if (col.dataset.sortKey === state.key) {
                col.innerHTML = `${label} ${state.dir === 1 ? ICON_SORT_ASC : ICON_SORT_DESC}`;
            } else {
                col.textContent = label;
            }
            if (!col.dataset.label) col.dataset.label = label;
        });
    }

    // ---- Context menu -------------------------------------------------
    let _menuEl = null;
    function closeContextMenu() {
        if (_menuEl) { _menuEl.remove(); _menuEl = null; }
        document.removeEventListener('click', closeContextMenu, true);
        document.removeEventListener('keydown', _menuEsc, true);
    }
    function _menuEsc(e) { if (e.key === 'Escape') closeContextMenu(); }

    /** Show a small right-click menu at (x, y). `items` is an array of
     * {label, onClick, danger?, separator?}. */
    function showContextMenu(x, y, items) {
        closeContextMenu();
        const menu = document.createElement('div');
        menu.className = 'fb-context-menu';
        menu.innerHTML = items.map((it, i) => it.separator
            ? '<div class="fb-context-menu-sep"></div>'
            : `<div class="fb-context-menu-item${it.danger ? ' fb-context-menu-danger' : ''}" data-i="${i}">${escapeHtmlLocal(it.label)}</div>`
        ).join('');
        document.body.appendChild(menu);
        // Position, then clamp inside the viewport.
        const vw = window.innerWidth, vh = window.innerHeight;
        const r = menu.getBoundingClientRect();
        menu.style.left = Math.min(x, vw - r.width - 8) + 'px';
        menu.style.top = Math.min(y, vh - r.height - 8) + 'px';
        menu.querySelectorAll('.fb-context-menu-item').forEach(el => {
            el.addEventListener('click', () => {
                const it = items[+el.dataset.i];
                closeContextMenu();
                if (it && it.onClick) it.onClick();
            });
        });
        _menuEl = menu;
        // Defer listener registration so the click that opened the menu doesn't close it.
        setTimeout(() => {
            document.addEventListener('click', closeContextMenu, true);
            document.addEventListener('keydown', _menuEsc, true);
        }, 0);
    }

    function escapeHtmlLocal(s) {
        const d = document.createElement('div');
        d.textContent = s == null ? '' : String(s);
        return d.innerHTML;
    }

    return {
        ICON_DIR, ICON_FILE, ICON_SYMLINK,
        fmtBytes, fmtMtime,
        sortEntries, initSortableHeader,
        showContextMenu, closeContextMenu,
    };
})();

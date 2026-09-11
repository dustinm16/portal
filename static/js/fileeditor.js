/**
 * Open Relay Portal - CodeMirror wiring shared by the jailed game-server
 * config editor (admin.html inline script + dashboard.js, #gs-config-text)
 * and the admin file manager's edit modal (admin.html, #files-edit-textarea).
 *
 * CodeMirror 5 is vendored locally under static/js/vendor/codemirror/ (MIT,
 * LICENSE alongside it) rather than loaded from a CDN. `fromTextArea()`
 * replaces the <textarea> with a `.CodeMirror` div positioned in its place
 * and keeps the original element in the DOM (hidden) for a plain form
 * submit to fall back to — this app doesn't use that, so `.value` reads on
 * the underlying <textarea> after attaching are stale; use FileEditor's
 * getValue/setValue instead of touching `.value` directly once attached.
 */
const FileEditor = (() => {
    // Extension -> CodeMirror mode spec. Covers both the jailed game-server
    // browser's editable suffixes (_BROWSE_WRITE_SUFFIXES in gameservers.py)
    // and the broader set of text files the admin file manager can open
    // (any file on the host — systemd units, shell scripts, source, etc).
    // An extension with no entry gets `null` (no mode = plain text, still a
    // real editor with line numbers/undo, just no coloring).
    const MODE_BY_EXT = {
        // key=value / ini-ish
        ini: 'properties', cfg: 'properties', conf: 'properties', config: 'properties',
        properties: 'properties', props: 'properties', cnf: 'properties', settings: 'properties',
        service: 'properties', timer: 'properties', socket: 'properties', target: 'properties',
        mount: 'properties', desktop: 'properties', env: 'properties', gitconfig: 'properties',
        // data formats
        json: { name: 'javascript', json: true },
        yaml: 'yaml', yml: 'yaml',
        toml: 'toml',
        xml: { name: 'xml', htmlMode: false }, svg: { name: 'xml', htmlMode: false }, xsl: { name: 'xml', htmlMode: false },
        html: { name: 'xml', htmlMode: true }, htm: { name: 'xml', htmlMode: true },
        // scripting
        lua: 'lua',
        js: 'javascript', mjs: 'javascript', cjs: 'javascript',
        jsx: { name: 'javascript', jsx: true },
        py: 'python',
        sh: 'shell', bash: 'shell', zsh: 'shell',
        sql: 'text/x-sql',
        // markup / style
        css: 'css',
        md: 'markdown', markdown: 'markdown',
        // C-family
        c: 'text/x-csrc', h: 'text/x-csrc',
        cpp: 'text/x-c++src', hpp: 'text/x-c++src', cc: 'text/x-c++src', cxx: 'text/x-c++src',
        java: 'text/x-java',
        cs: 'text/x-csharp',
    };

    function modeFor(filename) {
        const base = (filename || '').split('/').pop() || '';
        const ext = base.includes('.') ? base.split('.').pop().toLowerCase() : '';
        return MODE_BY_EXT[ext] || null;
    }

    /** Replace `textarea` with a CodeMirror instance. Call once per textarea
     * (typically right after the surrounding modal markup is in the DOM);
     * reuse the returned instance for the modal's whole lifetime via
     * setValue/getValue/setMode/setReadOnly rather than re-attaching. */
    function attach(textarea, opts) {
        return CodeMirror.fromTextArea(textarea, Object.assign({
            lineNumbers: true,
            theme: 'portal',
            matchBrackets: true,
            autoCloseBrackets: true,
            tabSize: 4,
            indentUnit: 4,
            lineWrapping: false,
        }, opts || {}));
    }

    function setMode(cm, filename) {
        cm.setOption('mode', modeFor(filename));
    }

    function setReadOnly(cm, readOnly) {
        cm.setOption('readOnly', !!readOnly);
    }

    function setValue(cm, text) {
        cm.setValue(text || '');
        cm.clearHistory();
    }

    function getValue(cm) {
        return cm.getValue();
    }

    /** Call after the editor's container becomes visible (display:none ->
     * flex/block) — CodeMirror measures itself on attach, and a hidden
     * container measures as 0-size, so a freshly-opened modal renders an
     * empty/misaligned editor until this runs. A short delay lets the
     * display change actually apply first. */
    function refresh(cm) {
        setTimeout(() => cm.refresh(), 0);
    }

    return { modeFor, attach, setMode, setReadOnly, setValue, getValue, refresh };
})();

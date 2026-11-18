/**
 * Open Relay Portal - terminal key bar helpers
 *
 * Pure functions (no DOM access) so they can be tested under Node:
 * key sequences for the bar, sticky Ctrl/Alt handling, telling terminal
 * generated data from key input, paste cleaning and the multi-line paste
 * check, the bar's default visibility and the font size limits.
 */
(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.TermKeys = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var ESC = '\x1b';
    var ARROW_FINAL = { up: 'A', down: 'B', right: 'C', left: 'D' };
    var FONT_MIN = 8;
    var FONT_MAX = 28;
    var FONT_DEFAULT = 14;

    /**
     * Sequence a terminal sends for an arrow key. Applications such as vim and
     * less switch the terminal to "application cursor keys" mode and expect
     * ESC O x instead of ESC [ x.
     */
    function arrowSequence(direction, applicationMode) {
        var final = ARROW_FINAL[direction];
        if (!final) return '';
        return ESC + (applicationMode ? 'O' : '[') + final;
    }

    /** Control character for one typed character, or null when it has none. */
    function ctrlChar(ch) {
        if (ch.length !== 1) return null;
        var code = ch.charCodeAt(0);
        if ((code >= 0x61 && code <= 0x7a) || (code >= 0x41 && code <= 0x5a)) return String.fromCharCode(code & 0x1f);
        switch (ch) {
            case '@': case ' ': return '\x00';
            case '[': return '\x1b';
            case '\\': return '\x1c';
            case ']': return '\x1d';
            case '^': return '\x1e';
            case '_': case '/': return '\x1f';
            case '?': return '\x7f';
        }
        return null;
    }

    /**
     * Apply the armed sticky modifiers to the next piece of terminal input.
     * mods is { ctrl: bool, alt: bool }. Only a single typed character, Tab,
     * Enter, Backspace, Esc or an arrow sequence is changed; anything longer
     * (a paste, a word from a soft keyboard) is passed through unmodified.
     */
    function applyModifiers(data, mods) {
        var ctrl = !!(mods && mods.ctrl);
        var alt = !!(mods && mods.alt);
        if (!data || (!ctrl && !alt)) return data;

        var arrow = /^\x1b[\[O]([ABCD])$/.exec(data);
        if (arrow) {
            return ESC + '[1;' + (1 + (alt ? 2 : 0) + (ctrl ? 4 : 0)) + arrow[1];
        }

        var single = Array.from(data).length === 1;
        if (!single) return data;

        var out = data;
        if (ctrl) {
            var c = ctrlChar(data);
            if (c !== null) out = c;
        }
        if (alt) out = ESC + out;
        return out;
    }

    var REPORT_PATTERNS = [
        /^\x1b\[[IO]$/,                                  // focus in / out
        /^\x1b\[[?>=]?[\d;:]*c$/,                         // device attributes
        /^\x1b\[\??\d+n$/,                                 // status report
        /^\x1b\[\??\d+;\d+R$/,                            // cursor position report
        /^\x1b\[\??[\d;]*\$y$/,                           // mode report
        /^\x1b\[\d+(?:;\d+){1,2}t$/,                     // window size / position report
        /^\x1b\[<\d+;\d+;\d+[Mm]$/,                     // mouse report, SGR
        /^\x1b\[M[\s\S]{3}$/,                            // mouse report, X10
        /^\x1b\][\s\S]*(?:\x07|\x1b\\)$/,                // OSC reply
        /^\x1bP[\s\S]*\x1b\\$/                           // DCS reply
    ];

    /**
     * Data the terminal itself sends back (focus reports, replies to queries
     * from the running program, mouse reports) as opposed to a key the user
     * pressed. These must not use up an armed Ctrl or Alt.
     */
    function isTerminalReport(data) {
        if (!data || data.charAt(0) !== ESC) return false;
        for (var i = 0; i < REPORT_PATTERNS.length; i++) {
            if (REPORT_PATTERNS[i].test(data)) return true;
        }
        return false;
    }

    /**
     * Text about to be pasted: drop the bracketed-paste end marker and every
     * other C0 control character except tab, carriage return and line feed. A
     * hidden ESC [ 2 0 1 ~ would end bracketed paste early and let the rest run
     * as typed input.
     */
    function sanitizePaste(text) {
        return String(text == null ? '' : text)
            .replace(/\x1b\[201~/g, '')
            .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '');
    }

    /** Line count of a text about to be pasted; a trailing line break adds no line. */
    function countLines(text) {
        if (!text) return 0;
        return text.replace(/\r\n|\r/g, '\n').replace(/\n$/, '').split('\n').length;
    }

    /**
     * A paste that contains a line break would run commands as soon as it
     * arrives (outside bracketed paste mode), so it needs a confirmation. This
     * includes a single line that ends in a line break.
     */
    function pasteNeedsConfirm(text) {
        return /[\r\n]/.test(text || '');
    }

    /** Is the key bar shown? A stored '1' or '0' wins; otherwise only on touch devices. */
    function keybarVisible(stored, coarsePointer) {
        if (stored === '1') return true;
        if (stored === '0') return false;
        return !!coarsePointer;
    }

    /** Font size for the next step, kept inside the supported range. */
    function clampFontSize(size) {
        var n = Math.round(Number(size));
        if (!isFinite(n)) return FONT_DEFAULT;
        return Math.min(FONT_MAX, Math.max(FONT_MIN, n));
    }

    return {
        FONT_MIN: FONT_MIN,
        FONT_MAX: FONT_MAX,
        FONT_DEFAULT: FONT_DEFAULT,
        arrowSequence: arrowSequence,
        applyModifiers: applyModifiers,
        isTerminalReport: isTerminalReport,
        sanitizePaste: sanitizePaste,
        countLines: countLines,
        pasteNeedsConfirm: pasteNeedsConfirm,
        keybarVisible: keybarVisible,
        clampFontSize: clampFontSize
    };
});

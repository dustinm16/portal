/**
 * Open Relay Portal - Terminal Client
 */

let term = null;
let ws = null;
let fitAddon = null;
let currentServiceId = null;
let currentWsPath = null;
let refit = function () {};

// Input goes through one dispatcher so that the key bar, the soft keyboard and
// the one-shot prompts (password, press any key to reconnect) all see it.
const inputListeners = [];
const keyMods = { ctrl: false, alt: false };

const STORAGE_KEYBAR = 'portal.terminal.keybar';
const STORAGE_FONT = 'portal.terminal.fontsize';

function storageGet(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return null; }
}

function storageSet(key, value) {
    try { window.localStorage.setItem(key, value); } catch (e) { /* storage blocked */ }
}

function onInput(fn) {
    inputListeners.push(fn);
    return {
        dispose() {
            const i = inputListeners.indexOf(fn);
            if (i >= 0) inputListeners.splice(i, 1);
        }
    };
}

function emitInput(data) {
    // Focus reports and replies to queries are sent by the terminal itself, not
    // typed: they pass through untouched and leave an armed Ctrl or Alt alone.
    let out = data;
    if (!TermKeys.isTerminalReport(data)) {
        out = TermKeys.applyModifiers(data, keyMods);
        clearModifiers();
    }
    inputListeners.slice().forEach(fn => fn(out));
}

/**
 * Initialize terminal for a service
 */
function initTerminal(serviceId, wsPath) {
    currentServiceId = serviceId;
    currentWsPath = wsPath;

    // Create terminal instance
    term = new Terminal({
        cursorBlink: true,
        fontSize: TermKeys.clampFontSize(storageGet(STORAGE_FONT) || TermKeys.FONT_DEFAULT),
        fontFamily: '"Cascadia Code", "Fira Code", "Monaco", "Consolas", monospace',
        theme: {
            background: '#0d1117',
            foreground: '#c9d1d9',
            cursor: '#58a6ff',
            cursorAccent: '#0d1117',
            selection: 'rgba(56, 139, 253, 0.4)',
            black: '#484f58',
            red: '#ff7b72',
            green: '#3fb950',
            yellow: '#d29922',
            blue: '#58a6ff',
            magenta: '#bc8cff',
            cyan: '#39c5cf',
            white: '#b1bac4',
            brightBlack: '#6e7681',
            brightRed: '#ffa198',
            brightGreen: '#56d364',
            brightYellow: '#e3b341',
            brightBlue: '#79c0ff',
            brightMagenta: '#d2a8ff',
            brightCyan: '#56d4dd',
            brightWhite: '#f0f6fc'
        },
        allowProposedApi: true
    });

    // Initialize fit addon
    fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);

    // Key bar state is applied before the first fit so the layout is final
    initKeybar();

    // Open terminal in container
    const container = document.getElementById('terminal-container');
    term.open(container);

    // Fit terminal to container
    fitAddon.fit();

    // Connect to service
    connect();

    // Handle window resize (and the on-screen keyboard, see initKeybar)
    refit = debounce(() => {
        fitAddon.fit();
        sendResize();
    }, 100);
    window.addEventListener('resize', refit);
    syncViewport();

    // Handle terminal input
    term.onData(emitInput);
    onInput(data => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'input',
                data: data
            }));
        }
    });

    // Focus terminal
    term.focus();
}

/**
 * Mobile key bar: Esc, Tab, sticky Ctrl/Alt, arrows, a few symbols that are
 * hard to find on a phone keyboard, paste and font size.
 */
function clearModifiers() {
    keyMods.ctrl = false;
    keyMods.alt = false;
    const bar = document.getElementById('keybar');
    if (!bar) return;
    bar.querySelectorAll('[data-mod]').forEach(b => b.setAttribute('aria-pressed', 'false'));
}

function setKeybar(visible, remember) {
    document.body.classList.toggle('keybar-on', visible);
    const toggle = document.getElementById('keybar-toggle');
    if (toggle) toggle.setAttribute('aria-pressed', visible ? 'true' : 'false');
    if (!visible) clearModifiers();
    if (remember) storageSet(STORAGE_KEYBAR, visible ? '1' : '0');
    refit();
}

function setFontSize(size) {
    const next = TermKeys.clampFontSize(size);
    if (next === term.options.fontSize) return;
    term.options.fontSize = next;
    storageSet(STORAGE_FONT, String(next));
    fitAddon.fit();
    sendResize();
}

/** Keep the page the size of what is visible when the on-screen keyboard is open. */
function syncViewport() {
    const vv = window.visualViewport;
    if (!vv || vv.scale > 1.01) return;
    const style = document.documentElement.style;
    style.setProperty('--vv-height', vv.height + 'px');
    style.setProperty('--vv-top', vv.offsetTop + 'px');
    refit();
}

function pressKey(name) {
    switch (name) {
        case 'esc': emitInput('\x1b'); break;
        case 'tab': emitInput('\t'); break;
        case 'up': case 'down': case 'left': case 'right':
            emitInput(TermKeys.arrowSequence(name, !!(term.modes && term.modes.applicationCursorKeysMode)));
            break;
    }
}

function toggleModifier(name) {
    keyMods[name] = !keyMods[name];
    const btn = document.querySelector('#keybar [data-mod="' + name + '"]');
    if (btn) btn.setAttribute('aria-pressed', keyMods[name] ? 'true' : 'false');
}

/** Does the terminal's input box have the focus (is the on-screen keyboard meant to be open)? */
function termHasFocus() {
    return !!(term && term.textarea && document.activeElement === term.textarea);
}

// Whether a key bar tap should hand the focus back to the terminal afterwards.
let barRefocus = null;
let pasteRefocus = false;

/** Clean the text and send it to the terminal as a paste. */
function pasteToTerminal(text) {
    const clean = TermKeys.sanitizePaste(text);
    if (clean) term.paste(clean);
}

function showPasteDialog(text, hint) {
    const dialog = document.getElementById('paste-dialog');
    const area = document.getElementById('paste-text');
    const hintEl = document.getElementById('paste-hint');
    area.value = TermKeys.sanitizePaste(text);
    hintEl.textContent = hint;
    updatePasteLabel();
    dialog.hidden = false;
    area.focus();
}

function updatePasteLabel() {
    const text = document.getElementById('paste-text').value;
    const lines = TermKeys.countLines(text);
    const send = document.getElementById('paste-send');
    send.textContent = lines > 1 ? 'Paste ' + lines + ' lines' : 'Paste';
    send.disabled = !text;
}

function closePasteDialog() {
    document.getElementById('paste-dialog').hidden = true;
    if (pasteRefocus) term.focus();
}

/** Read the clipboard if the browser allows it; otherwise ask for a manual paste. */
async function pasteFromClipboard() {
    let text = null;
    try {
        if (navigator.clipboard && navigator.clipboard.readText) {
            text = await navigator.clipboard.readText();
        }
    } catch (e) {
        text = null;   // permission refused (iOS bubble, Firefox): use the text box
    }
    if (text === null) {
        showPasteDialog('', 'Paste into the box (long-press, then Paste), then send it to the terminal.');
        return;
    }
    text = TermKeys.sanitizePaste(text);
    if (!text) return;
    if (TermKeys.pasteNeedsConfirm(text)) {
        showPasteDialog(text, 'This text has more than one line and may run commands. Check it before pasting.');
        return;
    }
    pasteToTerminal(text);
    if (pasteRefocus) term.focus();
}

function initKeybar() {
    const bar = document.getElementById('keybar');
    if (!bar) return;
    const coarse = !!(window.matchMedia && window.matchMedia('(pointer: coarse)').matches);
    setKeybar(TermKeys.keybarVisible(storageGet(STORAGE_KEYBAR), coarse), false);

    const toggle = document.getElementById('keybar-toggle');
    toggle.addEventListener('click', () => {
        setKeybar(!document.body.classList.contains('keybar-on'), true);
        term.focus();
    });

    // A tap on a button must not take the focus from the terminal. Note whether
    // the terminal had it: if the user closed the on-screen keyboard it has not,
    // and the tap must not bring the keyboard back.
    bar.addEventListener('mousedown', e => {
        barRefocus = termHasFocus();
        e.preventDefault();
    });

    bar.addEventListener('click', e => {
        const btn = e.target.closest('button');
        if (!btn) return;
        const hadFocus = barRefocus !== null ? barRefocus : termHasFocus();
        barRefocus = null;
        if (btn.dataset.mod) {
            toggleModifier(btn.dataset.mod);
        } else if (btn.dataset.key) {
            pressKey(btn.dataset.key);
        } else if (btn.dataset.text) {
            emitInput(btn.dataset.text);
        } else if (btn.dataset.action === 'paste') {
            pasteRefocus = hadFocus;
            pasteFromClipboard();
            return;
        } else if (btn.dataset.action === 'font-smaller') {
            setFontSize(term.options.fontSize - 1);
        } else if (btn.dataset.action === 'font-larger') {
            setFontSize(term.options.fontSize + 1);
        }
        if (hadFocus) term.focus();
    });

    document.getElementById('paste-text').addEventListener('input', updatePasteLabel);
    document.getElementById('paste-send').addEventListener('click', () => {
        const text = document.getElementById('paste-text').value;
        document.getElementById('paste-dialog').hidden = true;
        pasteToTerminal(text);
        if (pasteRefocus) term.focus();
    });
    document.getElementById('paste-cancel').addEventListener('click', closePasteDialog);

    if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', syncViewport);
        window.visualViewport.addEventListener('scroll', syncViewport);
    }
}

/**
 * Connect to WebSocket
 */
function connect() {
    updateStatus('connecting', 'Connecting...');

    const wsUrl = Portal.getWebSocketUrl(currentWsPath);
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        updateStatus('connected', 'Connected');
        term.clear();
        sendResize();
    };

    ws.onmessage = (event) => {
        try {
            // Try to parse as JSON first (control messages)
            const data = JSON.parse(event.data);

            switch (data.type) {
                case 'connected':
                    term.writeln('\x1b[32m✓ Connected to terminal\x1b[0m\r\n');
                    sendResize();
                    break;
                case 'error':
                    term.writeln(`\x1b[31mError: ${data.message}\x1b[0m\r\n`);
                    break;
                case 'auth_required':
                    handleAuthRequired(data);
                    break;
                case 'host_key':
                    handleHostKey(data);
                    break;
                default:
                    // Unknown JSON message, might be terminal output
                    if (data.data) {
                        term.write(data.data);
                    }
            }
        } catch (e) {
            // Not JSON, treat as terminal output
            term.write(event.data);
        }
    };

    ws.onclose = (event) => {
        updateStatus('disconnected', 'Disconnected');

        if (event.code === 4001) {
            // The session was revoked (logout, sign-out everywhere, password reset):
            // reconnecting would only be refused, so go to the login page.
            window.location.replace('/login');
            return;
        }
        if (event.code === 4003) {
            term.writeln('\x1b[31mAccess denied - insufficient permissions\x1b[0m');
        } else if (event.code === 4004) {
            term.writeln('\x1b[31mService not found\x1b[0m');
        } else if (event.code !== 1000) {
            term.writeln(`\r\n\x1b[33mConnection closed (code: ${event.code})\x1b[0m`);
            term.writeln('\x1b[90mPress any key to reconnect...\x1b[0m');

            // Wait for keypress to reconnect
            const disposable = onInput(() => {
                disposable.dispose();
                reconnect();
            });
        }
    };

    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        updateStatus('disconnected', 'Error');
    };
}

/**
 * The server refused the SSH host key (not trusted yet, or changed).
 * Only the owner gets an Accept button; accepting reconnects.
 */
function handleHostKey(data) {
    const changed = data.state === 'changed';
    const colour = changed ? '31' : '33';
    term.writeln(`\x1b[${colour}m${changed ? 'Host key changed' : 'Host key not trusted yet'}\x1b[0m`);
    term.writeln(String(data.message || ''));
    term.writeln(`Fingerprint: ${data.fingerprint}${data.algorithm ? ' (' + data.algorithm + ')' : ''}`);
    if (changed && data.expected) term.writeln(`Accepted earlier: ${data.expected}`);
    term.writeln('');
    HostKey.prompt(data, { onAccepted: () => reconnect() });
}

/**
 * Handle SSH auth required
 */
function handleAuthRequired(data) {
    if (data.method === 'password') {
        if (data.needs_username) {
            term.writeln('Authentication required.');
            term.write('Username: ');
            promptInput(false, (username) => {
                term.write('Password: ');
                promptInput(true, (password) => {
                    ws.send(JSON.stringify({
                        type: 'auth',
                        username: username,
                        password: password
                    }));
                });
            });
        } else {
            term.writeln('Password authentication required.');
            term.write('Password: ');
            promptInput(true, (password) => {
                ws.send(JSON.stringify({
                    type: 'auth',
                    password: password
                }));
            });
        }
    }
}

function promptInput(hidden, callback) {
    let input = '';
    const disposable = onInput(char => {
        if (char === '\r' || char === '\n') {
            disposable.dispose();
            term.writeln('');
            callback(input);
        } else if (char === '\x7f') {
            if (input.length > 0) {
                input = input.slice(0, -1);
                if (!hidden) {
                    term.write('\b \b');
                }
            }
        } else if (char >= ' ') {
            input += char;
            if (!hidden) {
                term.write(char);
            }
        }
    });
}

/**
 * Reconnect to terminal
 */
function reconnect() {
    if (ws) {
        ws.close();
    }
    term.clear();
    connect();
}

/**
 * Send terminal resize
 */
function sendResize() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'resize',
            cols: term.cols,
            rows: term.rows
        }));
    }
}

/**
 * Update connection status
 */
function updateStatus(status, text) {
    const statusEl = document.getElementById('connection-status');
    const statusText = document.getElementById('status-text');

    statusEl.className = `connection-status ${status}`;
    statusText.textContent = text;
}

/**
 * Debounce function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if (ws) {
        ws.close(1000, 'Page closed');
    }
});

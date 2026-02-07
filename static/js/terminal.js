/**
 * Open Relay Portal - Terminal Client
 */

let term = null;
let ws = null;
let fitAddon = null;
let currentServiceId = null;
let currentWsPath = null;

/**
 * Initialize terminal for a service
 */
function initTerminal(serviceId, wsPath) {
    currentServiceId = serviceId;
    currentWsPath = wsPath;

    // Create terminal instance
    term = new Terminal({
        cursorBlink: true,
        fontSize: 14,
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

    // Open terminal in container
    const container = document.getElementById('terminal-container');
    term.open(container);

    // Fit terminal to container
    fitAddon.fit();

    // Connect to service
    connect();

    // Handle window resize
    window.addEventListener('resize', debounce(() => {
        fitAddon.fit();
        sendResize();
    }, 100));

    // Handle terminal input
    term.onData(data => {
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
                    break;
                case 'error':
                    term.writeln(`\x1b[31mError: ${data.message}\x1b[0m\r\n`);
                    break;
                case 'auth_required':
                    handleAuthRequired(data);
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

        if (event.code === 4003) {
            term.writeln('\x1b[31mAccess denied - insufficient permissions\x1b[0m');
        } else if (event.code === 4004) {
            term.writeln('\x1b[31mService not found\x1b[0m');
        } else if (event.code !== 1000) {
            term.writeln(`\r\n\x1b[33mConnection closed (code: ${event.code})\x1b[0m`);
            term.writeln('\x1b[90mPress any key to reconnect...\x1b[0m');

            // Wait for keypress to reconnect
            const disposable = term.onData(() => {
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
    const disposable = term.onData(char => {
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

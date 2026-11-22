// Runs the command palette object of static/js/portal.js under Node with stubs (no browser):
// a connection chosen in the palette opens in the open mode the member saved for it.
const fs = require('fs');
const path = require('path');
let failed = 0;
function check(name, ok, detail) {
    console.log((ok ? 'ok:   ' : 'FAIL: ') + name + (ok || !detail ? '' : '  (' + detail + ')'));
    if (!ok) failed++;
}
const src = fs.readFileSync(path.join(__dirname, '..', 'static', 'js', 'portal.js'), 'utf8');
const start = src.indexOf('    commandPalette: {');
const end = src.indexOf('     * Welcome tour for first-time users');
if (start < 0 || end < 0) { console.log('FAIL: could not find the palette in portal.js'); process.exit(1); }
let body = src.slice(start, end);
body = body.slice(0, body.lastIndexOf('/**')).trim().replace(/,\s*$/, '');
global.document = { getElementById: () => null };
global.window = { location: { href: '' } };
const calls = [];
global.connectTo = (id, mode) => calls.push([id, mode]);
const conns = [
    { id: 'a', name: 'Alpha', type: 'ssh', host: 'h', prefs: { open_mode: 'new' } },
    { id: 'b', name: 'Beta', type: 'http', host: 'h', prefs: { open_mode: 'same' } },
    { id: 'c', name: 'Gamma', type: 'http', host: 'h', prefs: { open_mode: 'embedded' } },
    { id: 'd', name: 'Delta', type: 'ssh', host: 'h', prefs: { open_mode: 'default' } },
    { id: 'e', name: 'Eps', type: 'ssh', host: 'h' },
    { id: 'f', name: 'Zeta', type: 'http', host: 'h', prefs: { open_mode: 'javascript:alert(1)' } },
];
global.Portal = { fetchJSON: async (u) => (u === '/api/connections' ? { connections: conns } : Promise.reject(new Error('x'))) };
const P = eval('({' + body + '})').commandPalette;
(async () => {
    P._items = [];
    P._filteredItems = [];
    await P._loadDynamic();
    const by = (n) => P._items.find((i) => i.name === n);
    for (const [n, want] of [['Alpha', 'new'], ['Beta', 'same'], ['Gamma', 'embedded'], ['Delta', 'default'], ['Eps', 'default'], ['Zeta', 'default']]) {
        calls.length = 0;
        P._select(by(n));
        check(`${n}: the palette opens it in "${want}"`, calls.length === 1 && calls[0][1] === want && calls[0][0] === by(n).id, JSON.stringify(calls));
    }
    global.ConnOrganiser = { core: { canEmbed: (c) => c.type === 'http' } };
    check('"embedded" on a type with no embedded page falls back to the default when the dashboard script says so',
        P._openModeOf({ type: 'ssh', prefs: { open_mode: 'embedded' } }) === 'default' && P._openModeOf({ type: 'http', prefs: { open_mode: 'embedded' } }) === 'embedded');
    process.exit(failed ? 1 : 0);
})();

// Runs the pure part of static/js/conn-organise.js under Node (no DOM, no browser).
// Printed by tests/test_dash_organise_client.py.
const core = require('../static/js/conn-organise.js');
let failed = 0;
function check(name, ok, detail) {
    console.log((ok ? 'ok:   ' : 'FAIL: ') + name + (ok || !detail ? '' : '  (' + detail + ')'));
    if (!ok) failed++;
}
const mk = (name, type, host, prefs) => ({ id: name.toLowerCase(), name, type, host, prefs });
const P = (folder, tags, extra) => Object.assign({ folder: folder || '', tags: tags || [], open_mode: 'default', pinned: false, last_opened_at: null }, extra || {});

const conns = [
    mk('Palworld', 'ssh', '10.0.0.5', P('Games', ['survival'])),
    mk('Minecraft', 'ssh', '10.0.0.6', P('Games', ['survival', 'co-op'], { pinned: true })),
    mk('Router', 'http', '192.168.1.1', P('', ['network'])),
    mk('Plex', 'plex', '', P('Media', [])),
    mk('Zed', 'vnc', '10.9.9.9', undefined),
];

// typing "pal" filters to the Palworld card and Enter would open the first match
let m = core.orderedMatches(conns, core.queryWords('pal'), []);
check('"pal" matches only Palworld', m.length === 1 && m[0].name === 'Palworld', JSON.stringify(m.map(c => c.name)));
check('the first match is what Enter opens', core.orderedMatches(conns, core.queryWords('PAL'), [])[0].id === 'palworld');
check('an empty filter matches everything', core.orderedMatches(conns, [], []).length === 5);
check('the filter reads the host', core.orderedMatches(conns, core.queryWords('192.168'), []).map(c => c.name).join() === 'Router');
check('the filter reads the type', core.orderedMatches(conns, core.queryWords('vnc'), []).map(c => c.name).join() === 'Zed');
check('the filter reads the folder', core.orderedMatches(conns, core.queryWords('media'), []).map(c => c.name).join() === 'Plex');
check('the filter reads the tags', core.orderedMatches(conns, core.queryWords('network'), []).map(c => c.name).join() === 'Router');
check('every word must match', core.orderedMatches(conns, core.queryWords('games co-op'), []).map(c => c.name).join() === 'Minecraft');
check('an item without a host is still found by name and not by an empty host',
    core.orderedMatches(conns, core.queryWords('plex'), []).length === 1 && core.orderedMatches(conns, core.queryWords('undefined'), []).length === 0);
check('tag chips filter (all chosen tags)', core.orderedMatches(conns, [], ['survival', 'co-op']).map(c => c.name).join() === 'Minecraft');
check('one tag chip', core.orderedMatches(conns, [], ['survival']).length === 2);

// folders: named by name, unfiled last, pinned first
const g = core.groupByFolder(conns);
check('folders sort by name with the unfiled group last', g.map(x => x.folder).join('|') === 'Games|Media|', g.map(x => x.folder).join('|'));
check('a pinned item leads its folder', g[0].items[0].name === 'Minecraft', g[0].items.map(c => c.name).join());
check('items without prefs read as unfiled and unpinned', g[2].items.some(c => c.name === 'Zed') && core.prefsOf(conns[4]).folder === '');

// recently used: last 5 by time, newest first
const many = [];
for (let i = 1; i <= 8; i++) many.push(mk('C' + i, 'ssh', 'h', P('', [], { last_opened_at: '2030-01-0' + i + 'T10:00:00Z' })));
many.push(mk('Never', 'ssh', 'h', P()));
const r = core.recentItems(many, 5);
check('recently used holds the last 5 opened, newest first', r.map(c => c.name).join() === 'C8,C7,C6,C5,C4', r.map(c => c.name).join());
check('an item never opened is not in it', !core.recentItems(many, 20).some(c => c.name === 'Never'));
check('no opened items means an empty row', core.recentItems(conns, 5).length === 0);

// tags
const tc = core.tagCounts(conns);
check('tag chips count their items, most used first', tc[0].tag === 'survival' && tc[0].count === 2 && tc.length === 3, JSON.stringify(tc));
check('tag text splits on commas and spaces', JSON.stringify(core.parseTags(' a, b  c,,d ')) === '["a","b","c","d"]');

// open modes
check('embedded is offered for HTTP-like types only', core.canEmbed({ type: 'http' }) && core.canEmbed({ type: 'plex' }) && !core.canEmbed({ type: 'ssh' }) && !core.canEmbed({ type: 'vnc' }) && !core.canEmbed({ type: 'redis' }));
check('the four open modes', core.OPEN_MODES.map(x => x[0]).join() === 'default,same,new,embedded');

// "/" shortcut
const key = (o) => Object.assign({ key: '/', target: { tagName: 'BODY' } }, o);
check('"/" outside a field focuses the filter', core.isSlashShortcut(key()));
check('"/" inside an input does not', !core.isSlashShortcut(key({ target: { tagName: 'INPUT' } })));
check('"/" inside a textarea or select does not', !core.isSlashShortcut(key({ target: { tagName: 'TEXTAREA' } })) && !core.isSlashShortcut(key({ target: { tagName: 'SELECT' } })));
check('"/" in an editable element does not', !core.isSlashShortcut(key({ target: { tagName: 'DIV', isContentEditable: true } })));
check('"/" with a modifier does not', !core.isSlashShortcut(key({ ctrlKey: true })) && !core.isSlashShortcut(key({ metaKey: true })) && !core.isSlashShortcut(key({ altKey: true })));
check('another key does not', !core.isSlashShortcut(key({ key: 'a' })));
check('"/" while a dialog is open does not', !core.isSlashShortcut(key(), true) && core.isSlashShortcut(key(), false));
const disp = (m) => (n) => m.get(n);
const dlgA = { hidden: false }, dlgB = { hidden: false }, dlgC = { hidden: true };
check('a dialog is open when one of the nodes is shown', core.anyDialogOpen([dlgA, dlgB], disp(new Map([[dlgA, 'none'], [dlgB, 'flex']]))));
check('none open when all are none, empty or hidden', !core.anyDialogOpen([dlgA, dlgB, dlgC], disp(new Map([[dlgA, 'none'], [dlgB, ''], [dlgC, 'flex']]))) && !core.anyDialogOpen([], disp(new Map())));

process.exit(failed ? 1 : 0);

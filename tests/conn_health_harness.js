// Runs static/js/conn-health.js under Node: the tooltip words, then the polling and the dots against
// a tiny fake DOM and a fake Portal.fetch. No real browser, no real timers.
let failed = 0;
function check(name, ok, detail) {
    console.log((ok ? 'ok:   ' : 'FAIL: ') + name + (ok || !detail ? '' : '  (' + detail + ')'));
    if (!ok) failed++;
}

const core = require('../static/js/conn-health.js');
check('up with a latency', core.describe({ status: 'up', latency_ms: 12.4, since: 'x' }) === 'up, 12 ms');
check('up without a latency', core.describe({ status: 'up' }) === 'up');
const d = core.describe({ status: 'down', since: '2030-01-01T10:00:00Z' });
check('down says since a time', d.indexOf('down since ') === 0 && d.length > 12, d);
check('down with no usable time', core.describe({ status: 'down', since: 'nonsense' }) === 'down');
check('unknown, missing and unexpected statuses all read unknown',
    core.describe({ status: 'unknown' }) === 'status unknown' && core.describe(null) === 'status unknown'
    && core.statusOf({ status: '<script>' }) === 'unknown' && core.statusOf({ status: 'DOWN' }) === 'unknown');

class El {
    constructor(tag) { this.tagName = tag; this.attrs = {}; this.children = []; this.parentNode = null; this.className = ''; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
    appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
    removeChild(c) { this.children = this.children.filter(x => x !== c); c.parentNode = null; return c; }
    querySelector(sel) {
        const cls = sel.startsWith('.') ? sel.slice(1) : null;
        const find = (n) => { for (const c of n.children) { if ((cls && c.className.split(' ').includes(cls)) || (!cls && c.tagName === sel)) return c; const r = find(c); if (r) return r; } return null; };
        return find(this);
    }
}
const cards = [];
function card(id) {
    const c = new El('div'); c.className = 'connection-card'; c.setAttribute('data-conn-id', id);
    c.appendChild(new El('h4')); cards.push(c); return c;
}
const docListeners = {};
const intervals = [];
global.setInterval = (f, ms) => { intervals.push({ f, ms }); return intervals.length; };
global.document = {
    visibilityState: 'visible',
    createElement: (t) => new El(t),
    querySelectorAll: () => cards.slice(),
    addEventListener: (t, f) => { (docListeners[t] = docListeners[t] || []).push(f); },
};
global.window = global;
let answer = {};
let fetches = 0;
let fail = false;
global.Portal = { fetch: async (url) => { fetches++; if (fail) throw new Error('offline'); check('it asks the status route', url === '/api/connections/status'); return { ok: true, json: async () => answer }; } };

delete require.cache[require.resolve('../static/js/conn-health.js')];
require('../static/js/conn-health.js');
const H = global.ConnHealth;
const tick = () => new Promise(r => setImmediate(r));

(async () => {
    check('no dot is offered before the first answer', H.dot('a') === null);
    await tick();
    check('the first answer is fetched at once and polling is every 60 seconds', fetches === 1 && intervals.length === 1 && intervals[0].ms === 60000);
    check('the feature off (an empty map): still no dot', H.dot('a') === null);

    const ca = card('a'), cb = card('b');
    answer = { a: { status: 'up', latency_ms: 5, since: '2030-01-01T10:00:00Z' }, b: { status: 'down', latency_ms: null, since: '2030-01-01T10:00:00Z' } };
    await H.refresh();
    const da = ca.querySelector('.conn-health-dot'), db = cb.querySelector('.conn-health-dot');
    check('a dot is added to each card the answer names, inside the title', !!da && !!db && da.parentNode.tagName === 'h4');
    check('up dot: class, title and label', da.className.includes('conn-health-up') && da.getAttribute('title') === 'up, 5 ms' && da.getAttribute('aria-label').includes('up, 5 ms'));
    check('down dot says down since a time', db.className.includes('conn-health-down') && db.getAttribute('title').indexOf('down since ') === 0);
    check('a dot for a card being drawn now', H.dot('a') !== null && H.dot('zzz') === null);

    answer = { a: { status: 'down', since: '2030-01-01T11:00:00Z' } };
    await H.refresh();
    check('an update repaints the same dot in place', ca.children[0].children.length === 1 && da.className.includes('conn-health-down'));
    check('a card the answer no longer names loses its dot', cb.querySelector('.conn-health-dot') === null);

    answer = {};
    await H.refresh();
    check('the feature switched off: every dot goes', ca.querySelector('.conn-health-dot') === null);

    answer = { a: { status: '<img src=x onerror=alert(1)>', since: '<b>' } };
    await H.refresh();
    const dx = ca.querySelector('.conn-health-dot');
    check('an unexpected status is shown as unknown, never as markup', dx.className === 'conn-health-dot conn-health-unknown' && dx.getAttribute('title') === 'status unknown');

    const before = fetches;
    global.document.visibilityState = 'hidden';
    intervals[0].f();
    await tick();
    check('a hidden tab does not poll', fetches === before);
    global.document.visibilityState = 'visible';
    intervals[0].f();
    await tick();
    check('a visible tab polls', fetches === before + 1);

    fail = true;
    answer = { a: { status: 'up' } };
    await H.refresh();
    check('a failed poll keeps the last answer on the page', ca.querySelector('.conn-health-dot') !== null);

    const f2 = fetches;
    fail = false;
    await H.refresh();
    check('and the next poll works again', fetches === f2 + 1);
    if (failed) { console.log('\nconn_health_harness: ' + failed + ' FAILED'); process.exit(1); }
    console.log('\nconn_health_harness: all checks passed');
})();

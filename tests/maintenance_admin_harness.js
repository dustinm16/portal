// Runs static/js/maintenance-admin.js under Node against a tiny fake document.
// usage: node maintenance_admin_harness.js <maintenance-admin.js>   (prints one JSON object)
const path = require('path');
function node(tag) {
    const n = { tag, children: [], attrs: {}, listeners: {}, style: {}, value: '', checked: false, textContent: '', className: '' };
    n.appendChild = (c) => { n.children.push(c); return c; };
    n.setAttribute = (k, v) => { n.attrs[k] = v; };
    n.addEventListener = (ev, fn) => { n.listeners[ev] = fn; };
    return n;
}
const made = [];
global.document = { createElement: (t) => { const n = node(t); made.push(n); return n; },
                    createTextNode: (t) => ({ text: t }), getElementById: () => null,
                    addEventListener: () => {} };
const calls = [];
global.Portal = {
    fetch: async (url, opts) => { calls.push({ url, method: opts.method, body: opts.body ? JSON.parse(opts.body) : null });
        return { ok: true, status: 200, json: async () => ({ announcements: [], connections: [] }) }; },
    toast: () => {}
};
global.window = global;
const api = require(path.resolve(process.argv[2]));
const out = {};
async function clickSave(box) {
    const saves = made.filter((n) => n.textContent === 'Save' || n.textContent === 'Publish');
    await saves[saves.length - 1].listeners.click();
}
function inputs() { return made.filter((n) => n.tag === 'input' && n.attrs.type === 'datetime-local'); }
(async () => {
    const ended = { id: 7, level: 'info', body: 'old news', starts_at: '2026-10-01T08:00:30Z', ends_at: '2026-11-01T10:00:45Z', show_before_signin: false };
    made.length = 0; calls.length = 0;
    api.form({}, ended);
    await clickSave();
    out.unchanged = calls.find((c) => c.method === 'PUT').body;
    made.length = 0; calls.length = 0;
    api.form({}, ended);
    const [starts, ends] = inputs();
    ends.value = '2030-01-01T10:00';
    await clickSave();
    out.changedEnd = calls.find((c) => c.method === 'PUT').body;
    made.length = 0; calls.length = 0;
    api.form({}, null);
    const [s2, e2] = inputs();
    e2.value = '2030-01-01T10:00';
    await clickSave();
    out.create = calls.find((c) => c.method === 'POST').body;
    made.length = 0; calls.length = 0;
    const box = node('div');
    api.renderConnections(box, { connections: [{ id: 'abc/def', name: '<b>x</b>', owner: 'bob', owner_is_admin: false, maintenance_active: true, maintenance_until: null, maintenance_message: 'm' }] });
    const btn = made.find((n) => n.textContent === 'Clear maintenance');
    await btn.listeners.click();
    out.clear = calls.find((c) => c.method === 'POST');
    out.noMarkup = made.every((n) => !('innerHTML' in n));
    console.log(JSON.stringify(out));
})();

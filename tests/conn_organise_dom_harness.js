// Drives static/js/conn-organise.js against a tiny fake DOM: draws the list, filters, collapses a
// folder, pins, saves the dialog and opens the first match with Enter. No real browser.
let failed = 0;
function check(name, ok, detail) {
    console.log((ok ? 'ok:   ' : 'FAIL: ') + name + (ok || !detail ? '' : '  (' + detail + ')'));
    if (!ok) failed++;
}

class El {
    constructor(tag) {
        this.tagName = String(tag).toUpperCase(); this.children = []; this.attrs = {}; this.listeners = {};
        this.className = ''; this.parentNode = null; this._text = ''; this.hidden = false; this.style = {};
        this.value = ''; this.title = ''; this.type = ''; this.selected = false; this.id = '';
        this.classList = { toggle: (c, on) => { const l = this.className.split(' ').filter(Boolean).filter(x => x !== c); if (on) l.push(c); this.className = l.join(' '); } };
    }
    set textContent(v) { this.children = []; this._text = String(v); }
    get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
    set innerHTML(v) { this._text = ''; this.children = []; this._html = v; }
    get childNodes() { return this.children; }
    contains(n) { while (n) { if (n === this) return true; n = n.parentNode; } return false; }
    appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
    setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = v; }
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
    dispatch(t, ev) { (this.listeners[t] || []).forEach(f => f(Object.assign({ target: this, preventDefault() { this.prevented = true; }, stopPropagation() {} }, ev))); }
    focus() { document.activeElement = this; }
    select() {}
    click() { bubble(this, 'click'); }
    matchesSel(sel) {
        if (sel.startsWith('.')) return this.className.split(' ').includes(sel.slice(1));
        return this.tagName === sel.toUpperCase();
    }
    closest(sel) { let n = this; while (n) { if (n.matchesSel && n.matchesSel(sel)) return n; n = n.parentNode; } return null; }
    all(out = []) { this.children.forEach(c => { out.push(c); c.all(out); }); return out; }
    find(pred) { return this.all().filter(pred); }
}
function bubble(node, type, ev) {
    for (let n = node; n; n = n.parentNode) (n.listeners[type] || []).forEach(f => f(Object.assign({ target: node, preventDefault() {}, stopPropagation() {} }, ev)));
}

const ids = {};
['conn-filter', 'conn-filter-clear', 'conn-tag-chips', 'conn-recent', 'conn-recent-grid', 'inline-connections-grid',
 'conn-filter-none', 'conn-organise-modal', 'conn-organise-form', 'conn-organise-name', 'conn-organise-folder',
 'conn-organise-tags', 'conn-organise-folders', 'conn-organise-error', 'conn-organise-cancel', 'conn-organise-backdrop',
 'svc-filter', 'svc-filter-clear', 'svc-filter-none'].forEach(i => { const e = new El(i.includes('filter') && !i.includes('clear') && !i.includes('none') ? 'input' : 'div'); e.id = i; ids[i] = e; });
const docListeners = {};
const body = new El('body');
global.document = {
    readyState: 'complete', body: body, activeElement: null,
    getElementById: (i) => ids[i] || null,
    createElement: (t) => new El(t), createElementNS: (ns, t) => { const e = new El(t); e.ns = ns; return e; }, createTextNode: (t) => { const e = new El('#text'); e._text = t; return e; },
    addEventListener: (t, f) => { (docListeners[t] = docListeners[t] || []).push(f); },
    querySelector: () => null,
    querySelectorAll: (sel) => (String(sel).includes('.modal') ? [ids['conn-organise-modal']] : []),
};
global.window = global;
const store = {};
global.localStorage = { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = v; } };
const calls = [];
global.Portal = {
    toast() {},
    api: async (url, opt) => { calls.push({ url, opt }); const b = JSON.parse(opt.body); const cur = (global.__conns.find(c => url.includes('/' + c.id + '/')) || {}).prefs || {}; return { prefs: Object.assign({}, cur, b) }; },
};
const opened = [];
global.connectTo = (id, mode) => opened.push([id, mode]);
global.getConnectionIcon = () => '<svg></svg>';

require('../static/js/conn-organise.js');
const O = global.ConnOrganiser;
const P = (f, t, x) => Object.assign({ folder: f || '', tags: t || [], open_mode: 'default', pinned: false, last_opened_at: null }, x || {});
const conns = [
    { id: 'u1', name: 'Palworld', type: 'ssh', host: '10.0.0.5', port: 22, shared: true, owner_username: 'owner', prefs: P('Games', ['survival']) },
    { id: 'u2', name: 'Router', type: 'http', host: '192.168.1.1', port: 80, prefs: P('', ['network'], { last_opened_at: '2030-01-02T00:00:00Z' }) },
    { id: 'u3', name: 'Evil <img src=x onerror=alert(1)>', type: 'ssh', host: 'h', prefs: P('Games', []) },
];
global.__conns = conns;
O.show(conns, 7);

const grid = ids['inline-connections-grid'];
const cards = () => grid.find(n => n.className.includes('connection-card') && !n.className.includes('header') && !n.className.includes('actions') && !n.className.includes('details'));
check('all three cards are drawn', cards().length === 3, String(cards().length));
const heads = () => grid.find(n => n.className.includes('conn-folder-head'));
check('folders: Games and Unfiled', heads().length === 2 && heads()[0].textContent.includes('Games'), heads().map(h => h.textContent).join('|'));
check('a hostile name stays text (no element was made from it)', !grid.find(n => n.tagName === 'IMG').length && cards().some(c => c.textContent.includes('<img src=x')));
check('Recently used shows the opened one', ids['conn-recent'].hidden === false && ids['conn-recent-grid'].children.length === 1);
check('tag chips: survival and network', ids['conn-tag-chips'].children.length === 2 && ids['conn-tag-chips'].hidden === false);
check('no inline handler attribute anywhere in the drawn tree', !grid.all().concat(ids['conn-recent-grid'].all()).some(n => Object.keys(n.attrs).some(k => k.startsWith('on'))));

// filter "pal" then Enter
const input = ids['conn-filter'];
input.value = 'pal';
input.dispatch('input', {});
check('"pal" leaves the Palworld card only', cards().length === 1 && cards()[0].textContent.includes('Palworld'), String(cards().length));
input.dispatch('keydown', { key: 'Enter' });
check('Enter opens the first match with its open mode', opened.length === 1 && opened[0][0] === 'u1' && opened[0][1] === 'default', JSON.stringify(opened));
input.dispatch('keydown', { key: 'Escape' });
check('Escape clears the filter', input.value === '' && cards().length === 3);

// collapse a folder: click its head
heads()[0].click();
check('clicking a folder head collapses it and remembers it', cards().length === 1 && store['portal.dash.folders.7'] === '["Games"]', JSON.stringify(store));
check('the head says it is collapsed', heads()[0].getAttribute('aria-expanded') === 'false');
{
    const caret = heads()[0].children.find(c => c.className === 'conn-folder-caret');
    const svg = caret && caret.children[0];
    check('the folder caret is an inline SVG with no text character (U+25B6 is drawn as an emoji on phones)',
        svg && svg.tagName === 'SVG' && svg.ns === 'http://www.w3.org/2000/svg' && !/[\u25B6\u25BC\u25B8]/.test(heads()[0].textContent) && caret.getAttribute('data-state') === 'collapsed');
}
input.value = 'pal'; input.dispatch('input', {});
check('while filtering a collapsed folder is shown anyway', cards().length === 1 && cards()[0].textContent.includes('Palworld'));
input.value = ''; input.dispatch('input', {});
heads()[0].click();
check('clicking again expands it', cards().length === 3 && store['portal.dash.folders.7'] === '[]');

// tag chip filters
ids['conn-tag-chips'].children.find(c => c.textContent.startsWith('#network')).click();
check('a tag chip filters', cards().length === 1 && cards()[0].textContent.includes('Router'));
ids['conn-filter-clear'].click();
check('Clear removes the tag filter', cards().length === 3);

// pin through a card button: PUT {pinned:true}
const pal = () => cards().find(c => c.textContent.includes('Palworld'));
pal().find(n => n.getAttribute('data-act') === 'pin')[0].click();
await_();
async function await_() {
    await new Promise(r => setTimeout(r, 10));
    const last = calls[calls.length - 1];
    check('the pin button sends only the pin', last && last.url === '/api/connections/u1/prefs' && last.opt.method === 'PUT' && last.opt.body === '{"pinned":true}', JSON.stringify(last));
    check('the card is drawn pinned', pal().className.includes('connection-card-pinned'));

    // open mode select
    const sel = pal().find(n => n.getAttribute('data-act') === 'open-mode')[0];
    check('the open-mode choice is on the card', sel.children.map(o => o.value).join() === 'default,same,new,embedded' || sel.children.map(o => o.value).join() === 'default,same,new');
    sel.value = 'new';
    bubble(sel, 'change');
    await new Promise(r => setTimeout(r, 10));
    check('changing it saves only the open mode', calls[calls.length - 1].opt.body === '{"open_mode":"new"}');
    input.value = 'pal'; input.dispatch('input', {});
    input.dispatch('keydown', { key: 'Enter' });
    check('Enter now opens in the new mode', JSON.stringify(opened[opened.length - 1]) === '["u1","new"]', JSON.stringify(opened));
    input.value = ''; input.dispatch('input', {});

    // dialog
    pal().find(n => n.getAttribute('data-act') === 'organise')[0].click();
    check('the dialog opens with the stored folder and tags', ids['conn-organise-modal'].style.display === 'flex' && ids['conn-organise-folder'].value === 'Games' && ids['conn-organise-tags'].value === 'survival');
    check('the dialog takes focus', document.activeElement === ids['conn-organise-folder']);
    ids['conn-organise-folder'].value = 'Servers';
    ids['conn-organise-tags'].value = 'a, B  c';
    ids['conn-organise-form'].dispatch('submit', {});
    await new Promise(r => setTimeout(r, 10));
    check('saving sends folder and tags', calls[calls.length - 1].opt.body === '{"folder":"Servers","tags":["a","B","c"]}', calls[calls.length - 1].opt.body);
    check('the dialog closes and the card moved', ids['conn-organise-modal'].style.display === 'none' && heads().some(h => h.textContent.includes('Servers')), ids['conn-organise-modal'].style.display + ' ' + ids['conn-organise-error'].textContent + ' ' + heads().map(h => h.textContent).join('|'));

    // keys
    const slash = docListeners.keydown[0];
    const tab = new El('div'); tab.className = 'tab-content active'; tab.id = 'tab-my-connections';
    global.document.querySelector = (s) => (s === '.tab-content.active' ? tab : null);
    slash({ key: '/', target: { tagName: 'BODY' }, preventDefault() {} });
    check('"/" focuses the filter on the connections tab', document.activeElement === input);
    document.activeElement = null;
    slash({ key: '/', target: { tagName: 'INPUT' }, preventDefault() {} });
    check('"/" inside a field does nothing', document.activeElement === null);

    // "/" leaves the page alone while the dialog is open
    document.activeElement = null;
    pal().find(n => n.getAttribute('data-act') === 'organise')[0] && cards()[0].find(n => n.getAttribute('data-act') === 'organise')[0].click();
    check('the dialog is open for the "/" check', ids['conn-organise-modal'].style.display === 'flex');
    slash({ key: '/', target: { tagName: 'BODY' }, preventDefault() { check('"/" with a dialog open does not prevent the key', false); } });
    check('"/" with a dialog open does not take focus', document.activeElement !== input);
    ids['conn-organise-cancel'].click();
    check('the dialog closed again', ids['conn-organise-modal'].style.display === 'none');
    slash({ key: '/', target: { tagName: 'BODY' }, preventDefault() {} });
    check('"/" works again once the dialog is closed', document.activeElement === input);
    document.activeElement = null;

    // a failed save shows the error in the dialog
    global.Portal.api = async () => { throw new Error('Tag has a character that is not allowed'); };
    pal && cards()[0].find(n => n.getAttribute('data-act') === 'organise')[0].click();
    ids['conn-organise-form'].dispatch('submit', {});
    await new Promise(r => setTimeout(r, 10));
    check('a refused save keeps the dialog open and says why', ids['conn-organise-modal'].style.display === 'flex' && ids['conn-organise-error'].textContent.includes('not allowed'));
    ids['conn-organise-cancel'].click();

    // ---- keyboard and focus (1.22.0 review): fresh list, a working save again
    global.Portal.api = async (url, opt) => { calls.push({ url, opt }); const b = JSON.parse(opt.body); const cur = (global.__conns.find(c => url.includes('/' + c.id + '/')) || {}).prefs || {}; return { prefs: Object.assign({}, cur, b) }; };
    const conns2 = [
        { id: 'a1', name: 'Alpha', type: 'ssh', host: '10.0.0.1', port: 22, prefs: P('', ['x'], {}) },
        { id: 'b1', name: 'Beta', type: 'http', host: null, port: null, shared: true, owner_username: 'zed', prefs: P('', [], { last_opened_at: '2030-01-03T00:00:00Z' }) },
    ];
    global.__conns = conns2;
    O.show(conns2, 7);
    const alpha = () => cards().find(c => c.getAttribute('data-conn-id') === 'a1');
    const ctl = (card, act) => card.find(n => n.getAttribute('data-act') === act)[0];
    const sameControl = (act, id) => document.activeElement && grid.contains(document.activeElement)
        && document.activeElement.getAttribute('data-act') === act && document.activeElement.closest('.connection-card').getAttribute('data-conn-id') === id;
    check('a card with no host and no port prints neither "undefined" nor "null"',
        !grid.textContent.includes('undefined') && !grid.textContent.includes('null') && !ids['conn-recent-grid'].textContent.includes('undefined') && !ids['conn-recent-grid'].textContent.includes('null'));

    // (a) Enter with nothing to match, and during an input-method composition
    input.value = ''; input.dispatch('input', {});
    const before = opened.length;
    input.dispatch('keydown', { key: 'Enter' });
    check('Enter in an empty connections filter opens nothing', opened.length === before, JSON.stringify(opened.slice(before)));
    input.value = 'alp'; input.dispatch('input', {});
    input.dispatch('keydown', { key: 'Enter', isComposing: true });
    input.dispatch('keydown', { key: 'Enter', keyCode: 229 });
    check('Enter that confirms an input-method composition opens nothing', opened.length === before, JSON.stringify(opened.slice(before)));
    input.dispatch('keydown', { key: 'Enter' });
    check('a plain Enter with a filter still opens the first match', opened.length === before + 1 && opened[before][0] === 'a1');
    input.value = ''; input.dispatch('input', {});

    // (c) Recently used is hidden while a filter or a tag is active
    check('Recently used shows with no filter', ids['conn-recent'].hidden === false);
    input.value = 'alp'; input.dispatch('input', {});
    check('Recently used is hidden while a word filter is active', ids['conn-recent'].hidden === true);
    input.value = ''; input.dispatch('input', {});
    check('and shows again when the filter is cleared', ids['conn-recent'].hidden === false);

    // (b) focus returns to the same control of the same card after the grid is redrawn
    let old = ctl(alpha(), 'pin'); old.focus(); old.click();
    await new Promise(r => setTimeout(r, 10));
    check('after a pin the focus is on the pin button of the same card (a new node)', sameControl('pin', 'a1') && document.activeElement !== old);
    old = ctl(alpha(), 'open-mode'); old.focus(); old.value = 'same'; bubble(old, 'change');
    await new Promise(r => setTimeout(r, 10));
    check('after an open-mode change the focus is on that select of the same card', sameControl('open-mode', 'a1') && document.activeElement !== old);
    old = alpha().find(n => n.getAttribute('data-tag') === 'x')[0]; old.focus(); old.click();
    check('after a tag chip on a card the focus is on that chip of the same card',
        document.activeElement !== old && document.activeElement.getAttribute('data-tag') === 'x' && grid.contains(document.activeElement)
        && document.activeElement.closest('.connection-card').getAttribute('data-conn-id') === 'a1');
    check('Recently used is hidden while a tag is active', ids['conn-recent'].hidden === true);
    old = ids['conn-tag-chips'].children[0]; old.focus(); old.click();
    check('after a chip in the tag bar the focus is on that chip', document.activeElement !== old && ids['conn-tag-chips'].contains(document.activeElement) && document.activeElement.getAttribute('data-tag') === 'x');
    check('Recently used is back once no tag is active', ids['conn-recent'].hidden === false);
    old = ctl(ids['conn-recent-grid'].children[0], 'pin'); old.focus(); old.click();
    await new Promise(r => setTimeout(r, 10));
    check('a control in the Recently used row keeps the focus in that row',
        ids['conn-recent-grid'].contains(document.activeElement) && document.activeElement.getAttribute('data-act') === 'pin' && document.activeElement !== old);

    // the dialog: Save puts the focus back on the button that opened it
    const orgBtn = ctl(alpha(), 'organise'); orgBtn.focus(); orgBtn.click();
    ids['conn-organise-folder'].value = 'Box';
    ids['conn-organise-form'].dispatch('submit', {});
    await new Promise(r => setTimeout(r, 10));
    check('after Save in the dialog the focus is on the Folder and tags button of the same card', ids['conn-organise-modal'].style.display === 'none' && sameControl('organise', 'a1'),
        String(document.activeElement && document.activeElement.getAttribute && document.activeElement.getAttribute('data-act')));

    // (d) Tab stays inside the dialog
    const modal = ids['conn-organise-modal'];
    ids['conn-organise-folder'].tagName = 'INPUT'; ids['conn-organise-tags'].tagName = 'INPUT'; ids['conn-organise-cancel'].tagName = 'BUTTON';
    const saveBtn = new El('button'); saveBtn.type = 'submit';
    const closedBtn = new El('button'); closedBtn.disabled = true;
    [ids['conn-organise-backdrop'], ids['conn-organise-folder'], ids['conn-organise-tags'], ids['conn-organise-cancel'], closedBtn, saveBtn].forEach(n => modal.appendChild(n));
    ctl(alpha(), 'organise').click();
    const tabKey = (shift) => { const ev = { key: 'Tab', shiftKey: !!shift, preventDefault() { ev.p = true; } }; modal.dispatch('keydown', ev); return ev; };
    saveBtn.focus();
    let ev = tabKey(false);
    check('Tab on the last control of the dialog goes to the first', ev.p === true && document.activeElement === ids['conn-organise-folder']);
    ev = tabKey(true);
    check('Shift+Tab on the first control goes to the last (a disabled button is skipped)', ev.p === true && document.activeElement === saveBtn);
    ids['conn-organise-tags'].focus();
    ev = tabKey(false);
    check('Tab in the middle is left to the browser', !ev.p && document.activeElement === ids['conn-organise-tags']);
    document.activeElement = new El('a');
    ev = tabKey(false);
    check('Tab with the focus outside the dialog brings it in', ev.p === true && document.activeElement === ids['conn-organise-folder']);
    ids['conn-organise-cancel'].click();

    // Services tab: the text filter looks at the name and plugin only; Enter clicks the first card left
    const mkCard = (name, plugin, buttons) => {
        const c = new El('div'); c.className = 'service-card'; c.clicked = 0;
        const n = new El('div'); n.className = 'service-name'; n.textContent = name;
        const pl = new El('div'); pl.className = 'service-plugin'; pl.textContent = plugin;
        const act = new El('div'); act.textContent = buttons;
        [n, pl, act].forEach(x => c.appendChild(x));
        c.querySelector = (sel) => (sel === '.service-name' ? n : sel === '.service-plugin' ? pl : null);
        c.click = () => { c.clicked++; };
        return c;
    };
    const pal2 = mkCard('Palworld', 'Game Server', 'Stop Restart Logs Files Backup');
    const web = mkCard('Wiki', 'Proxy', 'Stop Restart Logs');
    global.document.querySelectorAll = (sel) => (sel === '#services-grid .service-card' ? [pal2, web] : String(sel).includes('.modal') ? [ids['conn-organise-modal']] : []);
    const sinput = ids['svc-filter'];
    sinput.value = 'pal'; sinput.dispatch('input', {});
    check('the services filter hides the other card', !pal2.className.includes('conn-hidden') && web.className.includes('conn-hidden'));
    sinput.dispatch('keydown', { key: 'Enter' });
    check('Enter on the services filter clicks the Palworld card', pal2.clicked === 1 && web.clicked === 0);
    sinput.value = 'logs'; sinput.dispatch('input', {});
    check('button labels are not searched ("logs" matches no card)', pal2.className.includes('conn-hidden') && web.className.includes('conn-hidden'));
    sinput.value = 'game'; sinput.dispatch('input', {});
    check('the plugin name is searched', !pal2.className.includes('conn-hidden') && web.className.includes('conn-hidden'));
    sinput.value = 'zzz'; sinput.dispatch('input', {});
    check('the Services tab says nothing matches when the filter hides every card', ids['svc-filter-none'].hidden === false);
    sinput.value = 'pal'; sinput.dispatch('input', {});
    check('and not while a card is shown', ids['svc-filter-none'].hidden === true);
    sinput.value = ''; sinput.dispatch('input', {});
    check('nor with an empty filter', ids['svc-filter-none'].hidden === true);
    pal2.clicked = 0; web.clicked = 0;
    sinput.dispatch('keydown', { key: 'Enter' });
    check('Enter in an empty services filter clicks no card', pal2.clicked === 0 && web.clicked === 0);
    sinput.value = 'pal'; sinput.dispatch('input', {});
    sinput.dispatch('keydown', { key: 'Enter', isComposing: true });
    sinput.dispatch('keydown', { key: 'Enter', keyCode: 229 });
    check('Enter that confirms an input-method composition clicks no card', pal2.clicked === 0);
    sinput.value = 'game'; sinput.dispatch('input', {});
    tab.id = 'tab-services';
    document.activeElement = null;
    slash({ key: '/', target: { tagName: 'BODY' }, preventDefault() {} });
    check('"/" on the Services tab focuses its filter', document.activeElement === sinput);
    process.exit(failed ? 1 : 0);
}

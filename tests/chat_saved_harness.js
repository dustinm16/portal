// Runs static/js/chat-saved.js (and static/js/portal.js beside it) under Node against a small fake DOM.
// The scripts are run one after the other with vm.runInContext in one context, so they share only the
// global object (window), exactly as separate classic scripts in a page do. Used by tests/test_saved_client.py.
// The time-zone checks run with the zone given in the TZ variable (the Python test runs this twice).
// usage: node chat_saved_harness.js <chat-saved.js> <portal.js>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

// ---------------------------------------------------------------- a small fake DOM
let active = null;
function matchOne(n, sel) {
  // one compound selector: tag, .class, [attr], [attr="v"], :not(.class)
  const rest = sel.trim();
  const re = /(^[a-z][a-z0-9]*)|(\.[\w-]+)|(\[[\w-]+(?:="[^"]*")?\])|(:not\(\.[\w-]+\))/gi;
  let m, used = '';
  while ((m = re.exec(rest))) {
    used += m[0];
    const t = m[0];
    if (m[1]) { if (n.tagName.toLowerCase() !== t.toLowerCase()) return false; }
    else if (m[2]) { if (!n.classList.contains(t.slice(1))) return false; }
    else if (m[3]) {
      const mm = /^\[([\w-]+)(?:="([^"]*)")?\]$/.exec(t);
      const name = mm[1];
      let v = n.getAttribute(name);
      if (v === null && name.startsWith('data-')) {
        const k = name.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
        v = n.dataset[k] === undefined ? null : n.dataset[k];
      }
      if (v === null) return false;
      if (mm[2] !== undefined && v !== mm[2]) return false;
    } else if (m[4]) { if (n.classList.contains(t.slice(6, -1))) return false; }
  }
  return used === rest;
}
function matches(n, selector) { return selector.split(',').some(s => matchOne(n, s)); }

class N {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase(); this.children = []; this.attrs = {}; this.listeners = {};
    this.parentNode = null; this.style = {}; this.dataset = {}; this.value = ''; this.disabled = false; this._cls = '';
    this._text = '';
    const self = this;
    this.classList = {
      contains: c => self._cls.split(/\s+/).includes(c),
      add: c => { if (!self.classList.contains(c)) self._cls = (self._cls + ' ' + c).trim(); },
      remove: c => { self._cls = self._cls.split(/\s+/).filter(x => x && x !== c).join(' '); },
    };
  }
  get className() { return this._cls; }
  set className(v) { this._cls = String(v); }
  set innerHTML(v) { throw new Error('innerHTML was used: ' + String(v).slice(0, 40)); }
  get innerHTML() { return ''; }
  set textContent(v) { this.children.forEach(c => { c.parentNode = null; }); this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); this._notify(c); return c; }
  append(...cs) { cs.forEach(c => this.appendChild(c)); }
  insertBefore(c, ref) { c.parentNode = this; const i = ref ? this.children.indexOf(ref) : -1; if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); this._notify(c); return c; }
  removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); c.parentNode = null; return c; }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  _notify(c) { if (this.observer) this.observer.cb([{ addedNodes: [c] }]); }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') idMap[v] = this; }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  focus() { active = this; }
  click() { return this.dispatch('click', {}); }
  scrollIntoView() {}
  getBoundingClientRect() { return { left: 10, top: 20 }; }
  contains(n) { for (let x = n; x; x = x.parentNode) if (x === this) return true; return false; }
  closest(sel) { for (let x = this; x; x = x.parentNode) if (x.tagName && matches(x, sel)) return x; return null; }
  all(sel) { const out = []; const walk = n => n.children.forEach(c => { if (matches(c, sel)) out.push(c); walk(c); }); walk(this); return out; }
  querySelectorAll(sel) { return this.all(sel); }
  querySelector(sel) { return this.all(sel)[0] || null; }
  dispatch(type, ev) {
    const e = Object.assign({ type, target: this, key: '', shiftKey: false, defaultPrevented: false, stopped: false,
                              preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.stopped = true; } }, ev);
    for (let x = this; x; x = x.parentNode) {
      e.currentTarget = x;
      for (const f of (x.listeners[type] || [])) f(e);
      if (e.stopped) break;
    }
    if (type === 'keydown' && this !== doc) for (const f of (doc.listeners.keydown || [])) { e.currentTarget = doc; f(e); }
    return e;
  }
  dispatchEvent(ev) { const e = this.dispatch(ev.type, ev); this.lastEvent = e; return !e.defaultPrevented; }
}
const idMap = {};
const doc = new N('#document');
doc.hidden = false;
doc.body = new N('body');
Object.defineProperty(doc, 'activeElement', { get: () => active });
doc.createElement = t => new N(t);
doc.getElementById = id => idMap[id] || null;
doc.readyState = 'complete';
doc.head = new N('head');

function mk(tag, id, cls) { const n = new N(tag); if (id) n.setAttribute('id', id); if (cls) n.className = cls; return n; }
function msgRow(id, text, extra) {
  const row = mk('div', null, 'message' + (extra ? ' ' + extra : ''));
  row.dataset.messageId = String(id);
  const header = mk('div', null, 'message-header');
  row.appendChild(header);
  const t = mk('div', null, 'message-text'); t.textContent = text; row.appendChild(t);
  return row;
}

// ---------------------------------------------------------------- the page
const container = mk('div', 'chat-messages');
const menu = mk('div', 'message-context-menu', 'context-menu');
const saveItem = mk('div', 'saved-menu-item', 'context-menu-item');
const remindItem = mk('div', 'remind-menu-item', 'context-menu-item');
const replyItem = mk('div', null, 'context-menu-item');
const hiddenItem = mk('div', null, 'context-menu-item'); hiddenItem.style.display = 'none';
menu.append(replyItem, saveItem, remindItem, hiddenItem);
const openBtn = mk('button', 'saved-open-btn');
[container, menu, openBtn].forEach(n => doc.body.appendChild(n));

const calls = [];
let marksPayload = { marks: [{ id: 11, kind: 'channel', message_id: 101 }], limits: { reminder_horizon_days: 366, max_saved: 500 } };
let listPages = [];
let nextSavedId = 50;
let marksStatus = 429;     // the first load of the marks is refused (a limit), the later ones answer
let entryStatus = 200;
let purgeStatus = 200;
const entryAt = {};        // before_id -> the one entry the single-entry read answers with
const apiLog = [];
async function fakeApi(method, path, body) {
  apiLog.push({ method, path, body });
  if (method === 'GET' && path === '/api/saved/marks') return marksStatus === 200 ? { status: 200, data: marksPayload } : { status: marksStatus, data: { error: 'Too many history requests' } };
  const one = /^\/api\/saved\?limit=1&before_id=(\d+)$/.exec(path);
  if (method === 'GET' && one) return entryStatus !== 200 ? { status: entryStatus, data: { error: 'Too many history requests' } } : { status: 200, data: { items: entryAt[+one[1]] ? [entryAt[+one[1]]] : [] } };
  if (method === 'GET' && path.startsWith('/api/saved?')) return { status: 200, data: listPages.shift() || { items: [], has_more: false } };
  if (method === 'POST' && path === '/api/saved') return { status: 201, data: { saved: { id: ++nextSavedId, kind: body.kind, message_id: body.message_id } } };
  if (method === 'DELETE' && path === '/api/saved/unavailable') return purgeStatus === 200 ? { status: 200, data: { removed: 2 } } : { status: purgeStatus, data: { error: 'Too many history requests' } };
  if (method === 'DELETE') return { status: 200, data: { status: 'removed' } };
  if (method === 'PUT') return body.remind_at === 'bad' ? { status: 400, data: { error: 'nope' } }
    : { status: 200, data: { id: +path.split('/')[3], remind_at: body.remind_at, reminded: false } };
  return { status: 404, data: {} };
}
const jumps = [], dms = [], toasts = [], menusHidden = [];
let view = 'channel';
const FIXED_NOW = new Date(2026, 2, 28, 12, 0, 0);   // Saturday 28 March 2026, 12:00 local time
let clock = FIXED_NOW;                                // what the module sees as now (moved by the refresh checks)

(async () => {
  const ctx = {
    document: doc, console, MouseEvent: class { constructor(type, init) { this.type = type; Object.assign(this, init); } },
    location: { protocol: 'https:', host: 'portal.test', pathname: '/chat', href: 'https://portal.test/chat', search: '' },
    localStorage: { getItem: () => null, setItem() {} }, navigator: {},
    setTimeout: () => 0, setInterval: () => 0, clearTimeout() {}, clearInterval() {},
    fetch: async (url, opts) => { calls.push({ url, opts }); return { ok: true, status: 200, json: async () => ({}) }; },
    open: (...a) => { ctx.opened = a; },
  };
  ctx.window = ctx;
  ctx.MutationObserver = class { constructor(cb) { this.cb = cb; } observe(node) { node.observer = this; } };
  vm.createContext(ctx);
  const src = fs.readFileSync(process.argv[2], 'utf8');
  vm.runInContext(fs.readFileSync(process.argv[3], 'utf8'), ctx, { filename: 'portal.js' });
  vm.runInContext(src, ctx, { filename: 'chat-saved.js' });
  const CS = ctx.ChatSaved;
  check('chat-saved.js sets window.ChatSaved as a separate classic script', CS && typeof CS.init === 'function' && typeof CS.open === 'function');

  // ---- time choices, in the zone of this run
  const tz = process.env.TZ || 'UTC';
  const choices = CS.remindChoices(FIXED_NOW);
  const byKey = Object.fromEntries(choices.map(c => [c.key, c]));
  const iso = d => CS.utcIso(d);
  const expect = {
    'Europe/Berlin': { hour: '2026-03-28T12:00:00Z', tomorrow: '2026-03-29T07:00:00Z', nextweek: '2026-03-30T07:00:00Z' },
    'America/New_York': { hour: '2026-03-28T17:00:00Z', tomorrow: '2026-03-29T13:00:00Z', nextweek: '2026-03-30T13:00:00Z' },
  }[tz];
  // 12:00 local on 28 March is 11:00Z in Berlin (still winter time; the clock changes the next night) and
  // 16:00Z in New York (summer time since 8 March)
  check(tz + ': in 1 hour is one hour from now', iso(byKey.hour.when) === expect.hour, iso(byKey.hour.when));
  check(tz + ': tomorrow 9:00 local across the clock change is the right UTC instant', iso(byKey.tomorrow.when) === expect.tomorrow, iso(byKey.tomorrow.when));
  check(tz + ': next week is the next Monday 9:00 local', iso(byKey.nextweek.when) === expect.nextweek && byKey.nextweek.when.getDay() === 1, iso(byKey.nextweek.when));
  const monday = new Date(2026, 2, 30, 8, 0, 0);
  check(tz + ': on a Monday, next week is the Monday a week away', CS.remindChoices(monday).find(c => c.key === 'nextweek').when.getDate() === 6
        && CS.remindChoices(monday).find(c => c.key === 'nextweek').when.getMonth() === 3);
  check('the UTC instant has the form the server wants', /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(iso(new Date())));
  const p = CS.parseLocalInput('2026-11-24T09:30');
  check(tz + ': a picker value is read as local time', p && p.getHours() === 9 && p.getMinutes() === 30 && p.getDate() === 24);
  check('an impossible date or text is refused', CS.parseLocalInput('2026-02-30T10:00') === null && CS.parseLocalInput('2026-13-01T10:00') === null
        && CS.parseLocalInput('soon') === null && CS.parseLocalInput('') === null);
  check('a past time and one beyond the horizon are refused, a good one is not',
        CS.whenProblem(new Date(FIXED_NOW.getTime() - 1000), FIXED_NOW, 366) !== ''
        && CS.whenProblem(new Date(FIXED_NOW.getTime() + 400 * 86400000), FIXED_NOW, 366) !== ''
        && CS.whenProblem(new Date(FIXED_NOW.getTime() + 3600000), FIXED_NOW, 366) === ''
        && CS.whenProblem(null, FIXED_NOW, 366) !== '');

  // ---- init: marks fetched, rows marked for this member only
  const row101 = msgRow(101, 'one'), row102 = msgRow(102, 'two');
  container.append(row101, row102);
  await CS.init({
    api: fakeApi, now: () => clock, currentKind: () => view,
    jumpToMessage: (c, m) => jumps.push([c, m]), openDm: c => dms.push(c),
    hideMenus: () => menusHidden.push(1), toast: (t, ty) => toasts.push([t, ty]), doc,
  });
  check('the marks load is asked for once at start, and a refused one still gives every message its actions button',
        apiLog.filter(a => a.path === '/api/saved/marks').length === 1 && row101.querySelector('.msg-actions-btn') !== null
        && row102.querySelector('.msg-actions-btn') !== null && !row101.classList.contains('saved-message'));
  marksStatus = 200;
  await CS.loadMarks();
  const header101 = row101.querySelector('.message-header');
  check('the marks come from one GET and rows of a saved message get the marker, before the actions button', row101.classList.contains('saved-message')
        && row101.querySelector('.saved-badge') && row101.querySelector('.saved-badge').textContent === 'Saved'
        && !row102.classList.contains('saved-message') && apiLog.filter(a => a.path === '/api/saved/marks').length === 2
        && header101.children.indexOf(row101.querySelector('.saved-badge')) < header101.children.indexOf(row101.querySelector('.msg-actions-btn')));
  const row103 = msgRow(103, 'three');
  marksPayload.marks.push({ id: 13, kind: 'channel', message_id: 103 });
  await CS.loadMarks();
  check('a row added later is marked by the observer', (container.appendChild(row103), row103.classList.contains('saved-message')));
  view = 'dm';
  CS.decorateAll();
  check('a saved channel message id is not a mark in a direct-message view', !row101.classList.contains('saved-message') && !row101.querySelector('.saved-badge'));
  view = 'channel';
  CS.decorateAll();
  check('and it is back in the channel view', row101.classList.contains('saved-message'));

  // ---- the message menu: save, then remove
  CS.prepareMenu(102);
  check('the menu says Save message for an unsaved message', saveItem.textContent === 'Save message');
  apiLog.length = 0;
  await saveItem.click(); await new Promise(r => setImmediate(r));
  check('Save sends kind and message id only', apiLog.length === 1 && apiLog[0].method === 'POST' && JSON.stringify(apiLog[0].body) === '{"kind":"channel","message_id":102}', JSON.stringify(apiLog));
  check('the row is marked at once and the menu was closed', row102.classList.contains('saved-message') && menusHidden.length >= 1);
  CS.prepareMenu(102);
  check('the menu now says Remove from Saved', saveItem.textContent === 'Remove from Saved');
  apiLog.length = 0;
  await saveItem.click(); await new Promise(r => setImmediate(r));
  check('Remove deletes the member own entry by its id and unmarks the row', apiLog.length === 1 && apiLog[0].method === 'DELETE' && /^\/api\/saved\/\d+$/.test(apiLog[0].path)
        && !row102.classList.contains('saved-message'), JSON.stringify(apiLog));

  // ---- Remind me: saves first, then offers the times
  apiLog.length = 0;
  CS.prepareMenu(104);
  await remindItem.click(); await new Promise(r => setImmediate(r));
  const dlg = doc.body.children.find(c => c.className.includes('saved-overlay-remind'));
  check('Remind me on an unsaved message saves it and opens the dialog', apiLog[0] && apiLog[0].method === 'POST' && dlg
        && dlg.querySelector('[role="dialog"]') !== null && ['hour', 'tomorrow', 'nextweek', 'custom', 'cancel'].every(k => dlg.querySelector('[data-choice="' + k + '"]')));
  check('no Clear button for a message without a reminder', dlg.querySelector('[data-choice="clear"]') === null);
  apiLog.length = 0;
  await dlg.querySelector('[data-choice="tomorrow"]').click(); await new Promise(r => setImmediate(r));
  const put = apiLog.find(a => a.method === 'PUT');
  check(tz + ': Tomorrow 9:00 sends the absolute UTC instant', put && put.body.remind_at === expect.tomorrow && /\/remind$/.test(put.path), JSON.stringify(put));
  check('the dialog closed and the member was told', !doc.body.children.some(c => c.className.includes('saved-overlay-remind')) && toasts.some(t => /Reminder set/.test(t[0])));

  // custom date: a past value is refused locally, a valid one is sent as UTC
  CS.prepareMenu(104);
  await remindItem.click(); await new Promise(r => setImmediate(r));
  const dlg2 = doc.body.children.find(c => c.className.includes('saved-overlay-remind'));
  const input = dlg2.querySelector('input');
  check('the picker is a datetime-local input with a minimum', input.getAttribute('type') === 'datetime-local' && input.getAttribute('min') === '2026-03-28T12:00');
  input.value = '2026-03-01T09:00';
  apiLog.length = 0;
  await dlg2.querySelector('[data-choice="custom"]').click();
  check('a past picker value is refused without a request', apiLog.length === 0 && /future/.test(dlg2.querySelector('.saved-error').textContent));
  input.value = '2026-04-02T18:15';
  await dlg2.querySelector('[data-choice="custom"]').click(); await new Promise(r => setImmediate(r));
  const put2 = apiLog.find(a => a.method === 'PUT');
  const want2 = CS.utcIso(new Date(2026, 3, 2, 18, 15));
  check(tz + ': a chosen date and time is sent as its UTC instant', put2 && put2.body.remind_at === want2, JSON.stringify(put2) + ' want ' + want2);

  // ---- Remind me on a message that is saved already: its current reminder is read, shown and can be cleared
  const toastsBefore = () => toasts.filter(t => /^Saved\./.test(t[0])).length;
  async function remindOn(id) {
    apiLog.length = 0;
    CS.prepareMenu(id);
    await remindItem.click(); await new Promise(r => setImmediate(r));
    const d = doc.body.children.find(c => c.className.includes('saved-overlay-remind'));
    return d;
  }
  const closeDlg = () => { const d = doc.body.children.find(c => c.className.includes('saved-overlay-remind')); if (d) d.querySelector('[data-choice="cancel"]').click(); };
  closeDlg();
  entryAt[14] = { id: 13, remind_at: '2026-04-01T07:00:00Z', reminded: false, available: true };      // message 103 is saved as entry 13
  const savedToasts0 = toastsBefore();
  let rd = await remindOn(103);
  check('Remind me on a saved message with a reminder reads that entry (one list read of one entry), saves nothing and says nothing was saved',
        apiLog.length === 1 && apiLog[0].path === '/api/saved?limit=1&before_id=14' && toastsBefore() === savedToasts0, JSON.stringify(apiLog));
  check('the dialog shows the current reminder, offers it in the picker and has a Clear reminder button',
        rd && /Current reminder: /.test(rd.textContent) && rd.textContent.indexOf(CS.formatWhen('2026-04-01T07:00:00Z')) >= 0
        && rd.querySelector('input').value === CS.localInputValue(new Date('2026-04-01T07:00:00Z')) && rd.querySelector('[data-choice="clear"]') !== null);
  apiLog.length = 0;
  await rd.querySelector('[data-choice="clear"]').click(); await new Promise(r => setImmediate(r));
  check('Clear reminder PUTs null for that entry and closes the dialog', apiLog.length === 1 && apiLog[0].method === 'PUT' && apiLog[0].path === '/api/saved/13/remind'
        && apiLog[0].body.remind_at === null && !doc.body.children.some(c => c.className.includes('saved-overlay-remind')) && toasts.some(t => t[0] === 'Reminder cleared'));
  entryAt[14] = { id: 13, remind_at: null, reminded: false, available: true };
  rd = await remindOn(103);
  check('a saved message with no reminder opens the dialog without a current time and without Clear', rd && !/Current reminder/.test(rd.textContent) && rd.querySelector('[data-choice="clear"]') === null && rd.querySelector('input').value === '');
  closeDlg();
  entryAt[14] = { id: 13, remind_at: '2026-03-01T07:00:00Z', reminded: true, available: true };
  rd = await remindOn(103);
  check('a reminder that already fired is not offered as a current one', rd && rd.querySelector('[data-choice="clear"]') === null && !/Current reminder/.test(rd.textContent));
  closeDlg();
  entryAt[14] = { id: 12, remind_at: '2026-04-01T07:00:00Z', reminded: false };                              // the entry is gone: the read gives another one
  rd = await remindOn(103);
  check('another entry answering the read is never taken for this one', rd && rd.querySelector('[data-choice="clear"]') === null);
  closeDlg();
  entryAt[14] = { id: 13, remind_at: '2026-04-01T07:00:00Z', reminded: false, available: true };
  entryStatus = 429;
  rd = await remindOn(103);
  check('when the read is refused the dialog still opens, without the current time', rd && rd.querySelector('[data-choice="custom"]') !== null && rd.querySelector('[data-choice="clear"]') === null);
  closeDlg();
  entryStatus = 200;
  // an unsaved message: Saved is said once, the dialog opens, and cancelling keeps it saved
  const before = toastsBefore();
  rd = await remindOn(160);
  check('Remind me on an unsaved message says Saved once and opens the dialog', rd && toastsBefore() === before + 1 && apiLog[0].method === 'POST');
  closeDlg();
  check('cancelling the dialog leaves the message saved', CS._state.marks.has('channel:160'));

  // ---- the Saved view
  listPages = [{ items: [
      { id: 21, available: true, kind: 'channel', channel_id: 3, channel_name: 'lobby', message_id: 301, saved_at: '2026-03-20T10:00:00Z',
        remind_at: '2026-04-01T07:00:00Z', reminded: false,
        message: { username: 'ann', text: '<img src=x onerror=alert(1)> hello', created_at: '2026-03-19T09:00:00Z', anonymous: false } },
      { id: 22, available: true, kind: 'dm', conversation_id: 7, message_id: 77, saved_at: '2026-03-19T10:00:00Z', remind_at: null, reminded: false,
        message: { username: 'bo', text: 'dm words', created_at: '2026-03-19T09:00:00Z' } },
      { id: 23, available: false, saved_at: '2026-03-18T10:00:00Z', remind_at: null, reminded: false }],
      has_more: true, next_before_id: 23 },
    { items: [{ id: 24, available: false, saved_at: '2026-03-17T10:00:00Z', remind_at: '2026-03-18T07:00:00Z', reminded: true }], has_more: false }];
  apiLog.length = 0;
  active = openBtn;
  openBtn.click(); await new Promise(r => setImmediate(r));
  const panel = CS._state.panel;
  check('the Saved button opens a labelled dialog and asks for the first page', panel && apiLog[0].path === '/api/saved?limit=30'
        && panel.dlg.getAttribute('role') === 'dialog' && panel.dlg.getAttribute('aria-modal') === 'true');
  const items = panel.list.children;
  check('three entries are listed', items.length === 3);
  check('untrusted text is shown as text and never as markup', items[0].textContent.includes('<img src=x onerror=alert(1)> hello') && items[0].querySelector('img') === null);
  check('an available entry names its channel, author and reminder', items[0].textContent.includes('ann') && items[0].textContent.includes('#lobby') && /Reminder:/.test(items[0].textContent));
  check('an unavailable entry shows only "No longer available" and its saved time',
        items[2].textContent.startsWith('No longer available') && !/#|ann|lobby|hello/.test(items[2].textContent)
        && items[2].all('button').map(b => b.textContent).join(',') === 'Remove');
  check('every control is a real button with type=button and no inline handler',
        panel.dlg.all('button').every(b => b.getAttribute('type') === 'button' && !('onclick' in b.attrs)));
  const more = panel.more;
  check('Load more is offered and asks for the next page by the cursor', more.style.display === '' && (await more.click(), await new Promise(r => setImmediate(r)), apiLog[apiLog.length - 1].path === '/api/saved?limit=30&before_id=23'));
  check('the second page is appended and the button goes', panel.list.children.length === 4 && panel.more.style.display === 'none'
        && /Reminder sent/.test(panel.list.children[3].textContent));
  // ---- Remove unavailable entries: shown only while a listed entry is unavailable, asks first, then removes and reloads
  const purgeBtn = panel.dlg.querySelector('[data-action="purge"]');
  const purgeYes = panel.dlg.querySelector('[data-action="purge-yes"]'), purgeNo = panel.dlg.querySelector('[data-action="purge-no"]');
  const shown = n => n.style.display !== 'none';
  check('the Saved view with unavailable entries offers "Remove unavailable entries", and no question yet',
        purgeBtn && purgeBtn.textContent === 'Remove unavailable entries' && shown(purgeBtn) && !shown(purgeYes) && !shown(purgeNo) && !shown(panel.dlg.querySelector('.saved-purge-text')));
  apiLog.length = 0;
  await purgeBtn.click();
  check('pressing it asks first (nothing is sent) and says it also removes entries not shown yet',
        apiLog.length === 0 && shown(purgeYes) && shown(purgeNo) && !shown(purgeBtn) && /not shown yet/.test(panel.dlg.querySelector('.saved-purge-text').textContent) && shown(panel.dlg.querySelector('.saved-purge-text')));
  check('the confirm buttons are on their own row below the question, not in the row of the opener',
        purgeYes.parentNode === purgeNo.parentNode && purgeYes.parentNode !== purgeBtn.parentNode
        && panel.dlg.children.indexOf(purgeBtn.parentNode) < panel.dlg.children.indexOf(panel.dlg.querySelector('.saved-purge-text'))
        && panel.dlg.children.indexOf(panel.dlg.querySelector('.saved-purge-text')) < panel.dlg.children.indexOf(purgeYes.parentNode));
  // a click that arrives at once (the second click of a double click or double tap) is not an answer
  await purgeYes.click(); await new Promise(r => setImmediate(r));
  check('a confirm click right after the question opened sends nothing and keeps the question', apiLog.length === 0 && shown(purgeYes) && !shown(purgeBtn));
  clock = new Date(FIXED_NOW.getTime() + 599);
  await purgeYes.click(); await new Promise(r => setImmediate(r));
  check('a confirm click 599 ms after the question opened still sends nothing', apiLog.length === 0 && shown(purgeYes));
  clock = new Date(FIXED_NOW.getTime() + 2000);
  await purgeYes.dispatch('click', { detail: 2 }); await new Promise(r => setImmediate(r));
  check('the second click of a double click (detail 2) sends nothing even after the interval', apiLog.length === 0 && shown(purgeYes));
  await purgeNo.click();
  check('Keep them sends nothing and puts the button back', apiLog.length === 0 && shown(purgeBtn) && !shown(purgeYes) && !shown(panel.dlg.querySelector('.saved-purge-text')));
  // asking again starts the interval again, from the new opening
  clock = FIXED_NOW;
  await purgeBtn.click(); await purgeYes.click(); await new Promise(r => setImmediate(r));
  check('a second asking is guarded again', apiLog.length === 0 && shown(purgeYes));
  await purgeNo.click();
  purgeStatus = 429;
  await purgeBtn.click(); clock = new Date(FIXED_NOW.getTime() + 700); await purgeYes.dispatch('click', { detail: 0 }); await new Promise(r => setImmediate(r));
  check('a refused removal says why, keeps the list and shows the button again',
        apiLog.length === 1 && apiLog[0].method === 'DELETE' && panel.list.children.length === 4 && shown(purgeBtn) && toasts.some(t => /Too many history requests/.test(t[0]) && t[1] === 'error'), JSON.stringify(apiLog));
  purgeStatus = 200;
  listPages = [{ items: [{ id: 21, available: true, kind: 'channel', channel_id: 3, channel_name: 'lobby', message_id: 301, saved_at: '2026-03-20T10:00:00Z', remind_at: null, reminded: false,
                           message: { username: 'ann', text: 'still here', created_at: '2026-03-19T09:00:00Z' } }], has_more: false }];
  apiLog.length = 0; toasts.length = 0;
  clock = FIXED_NOW;
  await purgeBtn.click(); clock = new Date(FIXED_NOW.getTime() + 700); await purgeYes.click(); await new Promise(r => setImmediate(r)); await new Promise(r => setImmediate(r));
  clock = FIXED_NOW;
  check('confirming sends DELETE /api/saved/unavailable, says how many went and reloads the list from the top',
        apiLog.length === 2 && apiLog[0].method === 'DELETE' && apiLog[0].path === '/api/saved/unavailable' && apiLog[1].method === 'GET' && apiLog[1].path === '/api/saved?limit=30'
        && toasts.some(t => t[0] === 'Removed 2 unavailable entries' && t[1] === 'success') && panel.list.children.length === 1 && /still here/.test(panel.list.textContent), JSON.stringify(apiLog));
  check('with no unavailable entry listed the button is gone', !shown(purgeBtn) && !shown(purgeYes) && !shown(purgeNo));
  listPages = [{ items: [{ id: 21, available: true, kind: 'channel', channel_id: 3, channel_name: 'lobby', message_id: 301, saved_at: '2026-03-20T10:00:00Z',
                           remind_at: '2026-04-01T07:00:00Z', reminded: false,
                           message: { username: 'ann', text: '<img src=x onerror=alert(1)> hello', created_at: '2026-03-19T09:00:00Z', anonymous: false } }], has_more: false }];
  CS.close();
  openBtn.click(); await new Promise(r => setImmediate(r));
  const panelJ = CS._state.panel;
  check('a view of available entries only has no such button', !shown(panelJ.dlg.querySelector('[data-action="purge"]')));
  panelJ.list.children[0].all('button').find(b => b.getAttribute('data-action') === 'jump').click();
  check('Jump uses the page jump-to-message with the ids and closes the view', jumps.length === 1 && jumps[0][0] === 3 && jumps[0][1] === 301 && CS._state.panel === null);
  const listReads = apiLog.filter(a => a.path === '/api/saved?limit=30').length;
  openBtn.click(); await new Promise(r => setImmediate(r));
  listPages.length = 0;
  check('a reopened view asks again (nothing is cached)', apiLog.filter(a => a.path === '/api/saved?limit=30').length === listReads + 1);

  // a DM entry jumps by opening the conversation
  CS._state.panel.list.textContent = '';
  listPages = [];
  CS.close();
  listPages = [{ items: [{ id: 22, available: true, kind: 'dm', conversation_id: 7, message_id: 77, saved_at: '2026-03-19T10:00:00Z', remind_at: null, reminded: false,
                           message: { username: 'bo', text: 'dm words', created_at: '2026-03-19T09:00:00Z' } }], has_more: false }];
  openBtn.click(); await new Promise(r => setImmediate(r));
  CS._state.panel.list.children[0].all('button').find(b => b.getAttribute('data-action') === 'jump').click();
  check('a direct-message entry opens its conversation', dms.length === 1 && dms[0] === 7);

  // remove from the view
  active = openBtn;
  listPages = [{ items: [{ id: 31, available: false, saved_at: '2026-03-18T10:00:00Z', remind_at: null, reminded: false }], has_more: false }];
  openBtn.click(); await new Promise(r => setImmediate(r));
  const gone = CS._state.panel.list.children[0];
  const purge31 = CS._state.panel.dlg.querySelector('[data-action="purge"]');
  check('a view whose only entry is unavailable offers the removal button', purge31 && purge31.style.display !== 'none');
  apiLog.length = 0;
  await gone.all('button').find(b => b.getAttribute('data-action') === 'remove').click(); await new Promise(r => setImmediate(r));
  check('Remove deletes the entry by id and takes it out of the list, and the empty text appears',
        apiLog[0].method === 'DELETE' && apiLog[0].path === '/api/saved/31' && CS._state.panel.list.children.length === 0
        && /Nothing saved yet/.test(CS._state.panel.status.textContent));
  check('removing the last unavailable entry by hand takes the button away', purge31.style.display === 'none');

  // ---- keyboard
  active = openBtn;
  doc.dispatch('keydown', { key: 'Escape', target: doc });
  check('Escape closes the view and puts focus back on the button that opened it', CS._state.panel === null && active === openBtn);

  active = null;
  const ke = container.dispatch('keydown', { key: 'ArrowDown', target: container });
  check('Arrow down on the message list focuses the first message', active === row101 && ke.defaultPrevented);
  row101.dispatch('keydown', { key: 'ArrowDown', target: row101 });
  check('Arrow down moves to the next message', active === row102);
  row102.dispatch('keydown', { key: 'ArrowUp', target: row102 });
  check('Arrow up moves back', active === row101);
  let ctxEvent = null;
  row101.addEventListener('contextmenu', e => { ctxEvent = e; menu.classList.add('show'); });
  row101.dispatch('keydown', { key: 'ContextMenu', target: row101 });
  check('the menu key on a focused message opens the message menu at that message', ctxEvent && ctxEvent.type === 'contextmenu' && ctxEvent.clientX > 0);
  check('focus lands on the first visible menu item and the hidden one is skipped', active === replyItem && !!active && active !== hiddenItem);
  menu.dispatch('keydown', { key: 'ArrowDown', target: replyItem });
  check('arrow keys move through the menu', active === saveItem);
  menusHidden.length = 0; apiLog.length = 0;
  CS.prepareMenu(101);
  menu.dispatch('keydown', { key: 'Enter', target: saveItem });
  await new Promise(r => setImmediate(r));
  check('Enter on Save or Remove acts like a click', apiLog.some(a => a.method === 'DELETE' && a.path === '/api/saved/11'), JSON.stringify(apiLog));
  menu.dispatch('keydown', { key: 'Escape', target: saveItem });
  check('Escape closes the menu and returns to the message', menusHidden.length >= 1 && active === row101);

  // ---- touch: a visible per-message button opens the same menu as the context-menu key
  let docClicks = 0;
  doc.body.addEventListener('click', () => { docClicks++; });     // stands for the page's click handler that closes the menus
  const btn101 = row101.querySelector('.msg-actions-btn'), btn102 = row102.querySelector('.msg-actions-btn');
  check('every message has one actions button, in its header', btn101 && btn102 && btn101.parentNode === row101.querySelector('.message-header')
        && row101.all('.msg-actions-btn').length === 1);
  CS.decorateAll(); CS.decorateAll();
  check('decorating again adds no second button', row101.all('.msg-actions-btn').length === 1 && row102.all('.msg-actions-btn').length === 1);
  check('the button is a labelled real button with a menu popup, no inline handler and no symbol character',
        btn102.tagName === 'BUTTON' && btn102.getAttribute('type') === 'button' && /Message actions/.test(btn102.getAttribute('aria-label'))
        && btn102.getAttribute('aria-haspopup') === 'menu' && !('onclick' in btn102.attrs) && /^[.]+$/.test(btn102.textContent));
  const sysRow = msgRow(990, 'joined', 'system'), newRow = msgRow(991, 'late');
  container.append(sysRow, newRow);
  check('a message added later gets the button (observer), a system line does not',
        newRow.querySelector('.msg-actions-btn') !== null && sysRow.querySelector('.msg-actions-btn') === null);
  let tapEvent = null;
  row102.addEventListener('contextmenu', e => { tapEvent = e; e.preventDefault(); menu.classList.add('show'); });
  menu.classList.remove('show'); active = null; docClicks = 0;
  btn102.click();
  check('tapping the button opens the message menu for that message (a contextmenu event on its row)',
        tapEvent && tapEvent.type === 'contextmenu' && tapEvent.target === row102 && tapEvent.clientX > 0 && menu.classList.contains('show'));
  check('the tap does not reach the page click handler that would close the menu again', docClicks === 0);
  check('focus moves to the first menu item', active === replyItem);
  menu.dispatch('keydown', { key: 'Escape', target: replyItem });
  check('Escape in the menu puts focus back on the button', active === btn102);
  docClicks = 0;
  row102.dispatch('click', { target: row102 });
  check('a click elsewhere on the message still reaches the page', docClicks === 1);

  // ---- returning to the tab refreshes the marks at most once a minute, unless something was saved or removed
  const marksGets = () => apiLog.filter(a => a.path === '/api/saved/marks').length;
  const settle = () => new Promise(r => setImmediate(r));
  clock = new Date(FIXED_NOW.getTime() + 1000);
  await CS.loadMarks();                                   // a load stamps the time
  let g = marksGets();
  doc.dispatch('visibilitychange', {}); doc.dispatch('visibilitychange', {}); await settle();
  check('two returns to the tab right after a load ask for no marks', marksGets() === g, marksGets() - g);
  clock = new Date(FIXED_NOW.getTime() + 1000 + 59000);
  doc.dispatch('visibilitychange', {}); await settle();
  check('a return 59 seconds after the last load still asks for nothing', marksGets() === g, marksGets() - g);
  clock = new Date(FIXED_NOW.getTime() + 1000 + 61000);
  doc.dispatch('visibilitychange', {}); doc.dispatch('visibilitychange', {}); await settle();
  check('a return after a minute asks once, and the second return right after it does not', marksGets() === g + 1, marksGets() - g);
  g = marksGets();
  CS.prepareMenu(150);
  await saveItem.click(); await settle();
  g = marksGets();
  doc.dispatch('visibilitychange', {}); await settle();
  check('a return after a save asks again at once', marksGets() === g + 1, marksGets() - g);
  doc.dispatch('visibilitychange', {}); await settle();
  check('and only once', marksGets() === g + 1);
  CS.prepareMenu(150);
  await saveItem.click(); await settle();                 // now it says Remove from Saved
  g = marksGets();
  doc.dispatch('visibilitychange', {}); await settle();
  check('a return after a removal asks again at once', marksGets() === g + 1, marksGets() - g);
  doc.hidden = true;
  clock = new Date(FIXED_NOW.getTime() + 1000 + 400000);
  doc.dispatch('visibilitychange', {}); await settle();
  check('going to the background asks for nothing', marksGets() === g + 1);
  doc.hidden = false;
  clock = FIXED_NOW;

  // ---- portal.js and chat-saved.js together
  check('portal.js sets window.Portal', ctx.Portal && typeof ctx.Portal.fetch === 'function');
  const CS2 = ctx.ChatSaved;
  const NB = vm.runInContext('NotificationBell', ctx);   // a top-level const of portal.js, as in a page
  CS2._state.cfg.api = undefined;      // use the page default: Portal.fetch
  calls.length = 0;
  await CS2.loadMarks();
  check('without an injected api the default goes through Portal.fetch with credentials', calls.length === 1 && calls[0].url === '/api/saved/marks'
        && calls[0].opts.credentials === 'same-origin', JSON.stringify(calls[0]));
  CS2._state.cfg.api = fakeApi;
  ctx.chatJumpToMessage = (c, m) => jumps.push(['n', c, m]);
  await NB.clickNotification(5, JSON.stringify({ channel_id: 3, message_id: 9, saved_id: 2 }));
  check('a reminder notification with a message opens it through the existing jump', jumps[jumps.length - 1].join() === 'n,3,9');
  listPages = [{ items: [], has_more: false }];
  await NB.clickNotification(6, JSON.stringify({ saved: 1, saved_id: 2 }));
  await new Promise(r => setImmediate(r));
  check('a reminder notification that could not open its message opens the Saved view', CS2._state.panel !== null);
  CS2.close();
  ctx.ChatSaved = undefined;
  await NB.clickNotification(7, JSON.stringify({ saved: 1 }));
  check('on a page without the Saved view the notification opens /chat?saved=1', ctx.opened && ctx.opened[0] === '/chat?saved=1');

  console.log(results.map(r => 'RESULT ' + JSON.stringify(r)).join('\n'));
})().catch(e => { console.log(results.map(r => 'RESULT ' + JSON.stringify(r)).join('\n')); console.log('RESULT ' + JSON.stringify({ name: 'the harness ran', ok: false, detail: String(e && e.stack || e) })); });

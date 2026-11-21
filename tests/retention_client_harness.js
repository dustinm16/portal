// Runs static/js/chat-retention.js under Node against a small fake DOM and a fake fetch.
// usage: node retention_client_harness.js <chat-retention.js>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const path = require('path');
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

// ---- fake DOM -------------------------------------------------------------------------------
class Node_ {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.style = {}; this.listeners = {}; this.parentNode = null; this._text = ''; this.value = ''; this.checked = false; this.disabled = false; }
  setAttribute(k, v) { this.attrs[k] = v; if (k === 'id') this.id = v; }
  appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
  insertBefore(c, ref) { c.parentNode = this; const i = ref ? this.children.indexOf(ref) : -1; if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); return c; }
  removeChild(c) { this.children = this.children.filter(x => x !== c); c.parentNode = null; }
  get firstChild() { return this.children[0] || null; }
  get nextSibling() { const i = this.parentNode.children.indexOf(this); return this.parentNode.children[i + 1] || null; }
  addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); }
  async click() { for (const fn of (this.listeners.click || [])) await fn({}); }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  all() { return [this].concat(...this.children.map(c => c.all())); }
}
const body = new Node_('body'), head = new Node_('head');
const header = new Node_('div'), clear = new Node_('button'), topic = new Node_('div');
clear.id = 'clear-channel-btn'; topic.id = 'channel-topic';
header.appendChild(clear); body.appendChild(header); body.appendChild(topic);
const byId = () => [body, head].flatMap(n => n.all());
global.document = {
  createElement: t => new Node_(t), head, body,
  getElementById: id => byId().find(n => n.id === id) || null,
};
const calls = [];
let script = [];            // queued fetch answers
global.fetch = async (url, init) => {
  calls.push({ url, method: init.method, body: init.body ? JSON.parse(init.body) : null });
  const a = script.shift() || { status: 200, data: {} };
  return { ok: a.status >= 200 && a.status < 300, status: a.status, json: async () => a.data };
};
const toasts = [];
let confirmAnswer = true, confirmTexts = [];
global.Portal = { toast: (m, k) => toasts.push([m, k]) };
global.confirm = (t) => { confirmTexts.push(t); return confirmAnswer; };
global.setTimeout = (fn) => { fn(); return 0; };
global.window = global; global.loadChannels = () => { calls.push({ url: 'loadChannels' }); };

const CR = require(path.resolve(process.argv[2]));

(async () => {
  // ---- pure helpers
  const NOW = Date.UTC(2026, 10, 21, 12, 0, 0);
  const iso = new Date(NOW + 3 * 3600 * 1000).toISOString();
  check('notice: empty when the channel follows the global setting', CR.noticeText(null, iso, NOW) === '' && CR.noticeText(undefined, iso, NOW) === '');
  const n = CR.noticeText(2, iso, NOW);
  check('notice: states the days and the next cleanup', /^Messages older than 2 days are removed, next cleanup about /.test(n) && n.endsWith('.'), n);
  check('notice: one day is singular', CR.noticeText(1, null, NOW) === 'Messages older than 1 day are removed.');
  check('notice: a cleanup time in the past reads as due', /next cleanup is due/.test(CR.noticeText(5, new Date(NOW - 1000).toISOString(), NOW)));
  check('parseDays: empty is null, forever is forever, numbers are numbers, junk is refused',
    CR.parseDays('').value === null && CR.parseDays('Forever').value === 'forever' && CR.parseDays(' 30 ').value === 30
    && !CR.parseDays('soon').ok && !CR.parseDays('-4').ok && !CR.parseDays('1.5').ok);
  check('retentionBody: both fields, confirm only when asked', JSON.stringify(CR.retentionBody('7', '', false).body) === '{"retention_days":7,"file_retention_days":null}'
    && CR.retentionBody('7', '3', true).body.confirm === true && !CR.retentionBody('x', '', false).ok);
  check('confirmText names the counts', /3 messages and 1 file /.test(CR.confirmText({ would_remove_messages: 3, would_remove_files: 1 })));
  const pb = CR.pruneBody({ from: '2026-11-21T10:00', to: '2026-11-21T11:00', user: ' bob ', skipPinned: true, dryRun: true });
  check('pruneBody: ISO range, user, skip_pinned, dry_run', pb.ok && /Z$/.test(pb.body.from) && pb.body.user === 'bob' && pb.body.skip_pinned === true && pb.body.dry_run === true);
  check('pruneBody: expected_count is carried for the real run', CR.pruneBody({ from: '2026-11-21T10:00', to: '2026-11-21T11:00', expected: 4 }).body.expected_count === 4);
  check('pruneBody: range required and ordered', !CR.pruneBody({ from: '', to: '2026-11-21T11:00' }).ok && !CR.pruneBody({ from: '2026-11-21T12:00', to: '2026-11-21T11:00' }).ok);
  check('pruneBody: no user key when empty, skip_pinned defaults to true', !('user' in CR.pruneBody({ from: '2026-11-21T10:00', to: '2026-11-21T11:00' }).body)
    && CR.pruneBody({ from: '2026-11-21T10:00', to: '2026-11-21T11:00' }).body.skip_pinned === true);

  // ---- the page
  const admin = { id: 1, role: 'admin' }, mod = { id: 2, role: 'moderator' }, member = { id: 3, role: 'user' };
  const info = (o) => Object.assign({ id: 7, name: 'room', mod_level: 'none', stream_chat: false, retention_days: null, file_retention_days: null }, o);
  CR.onChannelInfo(info({ mod_level: 'staff', retention_days: 2, retention_next_cleanup: iso }), admin);
  const btn = id => document.getElementById(id);
  check('an administrator sees Retention and Prune', btn('retention-btn').style.display === '' && btn('prune-btn').style.display === '');
  check('the notice is shown under the topic', /Messages older than 2 days/.test(btn('retention-note').textContent) && btn('retention-note').style.display === '');
  CR.onChannelInfo(info({ mod_level: 'staff' }), mod);
  check('a moderator sees Prune and not Retention', btn('prune-btn').style.display === '' && btn('retention-btn').style.display === 'none');
  check('no value: no notice', btn('retention-note').style.display === 'none');
  CR.onChannelInfo(info({ mod_level: 'none' }), member);
  check('an ordinary member sees neither', btn('prune-btn').style.display === 'none' && btn('retention-btn').style.display === 'none');
  CR.onModLevel('mod', member);
  check('a mod_level frame grants Prune', btn('prune-btn').style.display === '');
  CR.onChannelInfo(info({ mod_level: 'staff', stream_chat: true, retention_days: 5 }), admin);
  check('a stream chat: Prune yes, Retention and notice no', btn('prune-btn').style.display === '' && btn('retention-btn').style.display === 'none' && btn('retention-note').style.display === 'none');
  CR.onChannelInfo(null);
  check('a DM hides everything', btn('prune-btn').style.display === 'none' && btn('retention-btn').style.display === 'none');
  check('the controls are bound with listeners, none inline', !Object.keys(btn('prune-btn').attrs).some(k => k.startsWith('on')) && (btn('prune-btn').listeners.click || []).length === 1);

  // ---- retention dialog: shortening shows the count and needs the confirmation
  CR.onChannelInfo(info({ mod_level: 'staff', retention_days: 30 }), admin);
  await btn('retention-btn').click();
  let modal = body.children[body.children.length - 1];
  const inputs = modal.all().filter(x => x.tag === 'input');
  const save = modal.all().find(x => x.tag === 'button' && x.textContent === 'Save');
  check('the dialog shows the current value', inputs[0].value === '30');
  inputs[0].value = '2'; inputs[1].value = '1';
  calls.length = 0; confirmTexts = [];
  script = [{ status: 200, data: { applied: false, confirm_required: true, would_remove_messages: 12, would_remove_files: 3 } },
            { status: 200, data: { applied: true, retention_days: 2, file_retention_days: 1, next_cleanup_at: iso } }];
  await save.click();
  const puts = calls.filter(c => c.method === 'PUT');
  check('first PUT has no confirm, second has it', puts.length === 2 && !('confirm' in puts[0].body) && puts[1].body.confirm === true, JSON.stringify(puts));
  check('the confirm window shows the counts', confirmTexts.length === 1 && /12 messages and 3 files/.test(confirmTexts[0]), confirmTexts[0]);
  check('after saving the notice changes and the channels reload', /older than 2 days/.test(btn('retention-note').textContent) && calls.some(c => c.url === 'loadChannels'));
  // declined
  await btn('retention-btn').click();
  modal = body.children[body.children.length - 1];
  const inputs2 = modal.all().filter(x => x.tag === 'input');
  inputs2[0].value = '1';
  calls.length = 0; confirmAnswer = false;
  script = [{ status: 200, data: { applied: false, confirm_required: true, would_remove_messages: 5 } }];
  await modal.all().find(x => x.tag === 'button' && x.textContent === 'Save').click();
  check('declining the confirm sends nothing more', calls.filter(c => c.method === 'PUT').length === 1);
  confirmAnswer = true;
  // junk
  inputs2[0].value = 'soon'; calls.length = 0;
  await modal.all().find(x => x.tag === 'button' && x.textContent === 'Save').click();
  check('junk is refused in the dialog without a request', calls.length === 0 && /number of days/.test(modal.textContent));

  // ---- prune dialog: count first, then the real run echoes it
  CR.onChannelInfo(info({ mod_level: 'mod' }), mod);
  await btn('prune-btn').click();
  modal = body.children[body.children.length - 1];
  const pin = modal.all().find(x => x.tag === 'input' && x.checked === true);
  const find = t => modal.all().find(x => x.tag === 'button' && x.textContent.startsWith(t));
  const remove = find('Remove'), count = find('Count');
  check('Remove is disabled until a count was made', remove.disabled === true);
  check('keep pinned is on by default', !!pin);
  calls.length = 0; script = [{ status: 200, data: { count: 4, dry_run: true } }];
  await count.click();
  check('Count sends a dry run', calls[0].method === 'POST' && calls[0].body.dry_run === true && calls[0].body.skip_pinned === true && /\/channels\/7\/prune$/.test(calls[0].url), JSON.stringify(calls[0]));
  check('the count is shown before confirming', /4 messages would be removed/.test(modal.textContent) && remove.disabled === false && remove.textContent === 'Remove 4');
  calls.length = 0; confirmTexts = [];
  script = [{ status: 202, data: { started: true, count: 4 } }, { status: 200, data: { running: false, status: 'completed', removed: 4 } }];
  await remove.click();
  for (let i = 0; i < 30; i++) await new Promise(r => setImmediate(r));   // the status watcher runs on its own
  check('the real run echoes the count and is confirmed first', calls[0].body.expected_count === 4 && !('dry_run' in calls[0].body) && confirmTexts.length === 1 && /Remove 4 messages from #room/.test(confirmTexts[0]), JSON.stringify(calls[0]));
  check('the person who started it is told when it finished', toasts.some(t => /Prune finished: 4 messages removed/.test(t[0])), JSON.stringify(toasts));
  // 409: count changed
  await btn('prune-btn').click();
  modal = body.children[body.children.length - 1];
  const c2 = modal.all().find(x => x.tag === 'button' && x.textContent === 'Count'), r2 = modal.all().find(x => x.tag === 'button' && x.textContent.startsWith('Remove'));
  script = [{ status: 200, data: { count: 4 } }]; await c2.click();
  script = [{ status: 409, data: { error: 'The number of messages changed since the dry run; run it again', count: 9 } }];
  await r2.click();
  check('a 409 asks for a new count and disables Remove', /Now 9; count again/.test(modal.textContent) && r2.disabled === true);

  process.stdout.write(results.map(r => 'RESULT ' + JSON.stringify(r)).join('\n') + '\n');
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness crashed', ok: false, detail: e.stack })); });

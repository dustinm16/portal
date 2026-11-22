// Runs static/js/block-ref-admin.js under Node against a small fake document. Used by tests/test_blockref_ui.py.
// usage: node block_ref_harness.js <block-ref-admin.js>
'use strict';
const M = require(process.argv[2]);
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

class N {
  constructor(tag) { this.tagName = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this.disabled = false; }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  async fire(t, ev) { for (const f of (this.listeners[t] || [])) await f(ev || {}); }
  set textContent(v) { this.children = [{ tagName: '#text', text: String(v) }]; }
  get textContent() { return this.children.map(c => c.tagName === '#text' ? c.text : c.textContent).join(''); }
  set innerHTML(v) { throw new Error('innerHTML must never be assigned'); }
}
function find(n, pred) { for (const c of n.children || []) { if (pred(c)) return c; const r = find(c, pred); if (r) return r; } return null; }
function setup(responses) {
  const els = { 'block-ref-input': new N('INPUT'), 'block-ref-go': new N('BUTTON'), 'block-ref-result': new N('DIV') };
  const calls = [], toasts = []; let reloaded = 0;
  const doc = { getElementById: id => els[id] || null, createElement: t => new N(t.toUpperCase()) };
  const api = {
    fetch: async (url, opts) => { calls.push({ url, method: (opts && opts.method) || 'GET' }); const r = responses.shift();
      return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.body }; },
    toast: (m, t) => toasts.push([m, t]), reload: () => { reloaded++; }
  };
  const ui = M.create(doc, api);
  return { els, calls, toasts, ui, reloaded: () => reloaded };
}
const BLOCK = { ref: 'ABCD-EFGH', kind: 'block', limiter: 'ip_block', source: 'manual', address: '203.0.113.5',
  reason: '<img src=x onerror=alert(1)>', account: null, created_at: 'a', last_seen: 'b', hits: 3, active: true,
  block: { ip_address: '203.0.113.5', blocked_by_username: '<b>bob</b>', created_at: 'c', expires_at: null }, can_unblock: true };
(async () => {
  let t = setup([{ status: 200, body: BLOCK }]);
  check('the script mounts when its fields exist', !!t.ui);
  t.els['block-ref-input'].value = ' abcd-efgh ';
  await t.els['block-ref-go'].fire('click');
  check('a lookup calls the route with the trimmed, encoded ID', t.calls.length === 1 && t.calls[0].url === '/api/admin/blocks/ref/abcd-efgh', JSON.stringify(t.calls));
  const text = t.els['block-ref-result'].textContent;
  check('server text is shown as text and no markup is made from it', text.includes('<img src=x onerror=alert(1)>') && text.includes('<b>bob</b>'), text);
  check('active block, address and reason are shown', text.includes('Block active now: yes') && text.includes('203.0.113.5'));
  const btn = find(t.els['block-ref-result'], n => n.attrs && n.attrs.id === 'block-ref-unblock');
  check('a button to unblock is shown for an active block, wired with addEventListener', !!btn && (btn.listeners.click || []).length === 1);
  t.calls.length = 0;
  const more = [{ status: 200, body: {} }, { status: 200, body: Object.assign({}, BLOCK, { active: false, can_unblock: false }) }];
  t = setup([{ status: 200, body: BLOCK }].concat(more));
  t.els['block-ref-input'].value = 'ABCD-EFGH';
  await t.els['block-ref-go'].fire('click');
  const b2 = find(t.els['block-ref-result'], n => n.attrs && n.attrs.id === 'block-ref-unblock');
  await b2.fire('click');
  check('the unblock calls the existing DELETE route with the address and the reference',
        t.calls[1].method === 'DELETE' && t.calls[1].url === '/api/admin/blocked-ips/203.0.113.5?ref=ABCD-EFGH', JSON.stringify(t.calls));
  check('after the unblock the result is read again, shows the block inactive, no button, and the list reloads',
        t.calls.length === 3 && t.els['block-ref-result'].textContent.includes('Block active now: no')
        && !find(t.els['block-ref-result'], n => n.attrs && n.attrs.id === 'block-ref-unblock') && t.reloaded() === 1 && t.toasts[0][1] === 'success', JSON.stringify([t.calls.length, t.els['block-ref-result'].textContent, t.reloaded(), t.toasts]));
  t = setup([{ status: 200, body: { ref: 'ZZZZ-ZZZZ', kind: 'limit', limiter: 'login', address: '1.2.3.4', account: { id: 4, username: 'amy' }, hits: 1, can_unblock: false, active: null } }]);
  t.els['block-ref-input'].value = 'x';
  await t.els['block-ref-go'].fire('click');
  check('a rate-limit event shows the limiter and the account and has no unblock button',
        t.els['block-ref-result'].textContent.includes('Limiter: login') && t.els['block-ref-result'].textContent.includes('amy')
        && !find(t.els['block-ref-result'], n => n.attrs && n.attrs.id === 'block-ref-unblock'));
  t = setup([{ status: 404, body: {} }]);
  t.els['block-ref-input'].value = 'NOPE';
  await t.els['block-ref-go'].fire('click');
  check('a 404 says nothing was found and may have expired', /No event found/.test(t.els['block-ref-result'].textContent));
  t = setup([{ status: 429, body: {} }]);
  t.els['block-ref-input'].value = 'NOPE';
  await t.els['block-ref-go'].fire('click');
  check('a 429 says to wait', /Too many lookups/.test(t.els['block-ref-result'].textContent));
  t = setup([]);
  await t.els['block-ref-go'].fire('click');
  check('an empty field makes no request', t.calls.length === 0 && /Enter a reference/.test(t.els['block-ref-result'].textContent));
  results.forEach(r => console.log('RESULT ' + JSON.stringify(r)));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness crashed', ok: false, detail: e.stack })); });

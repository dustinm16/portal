// Loads static/js/portal.js and then static/js/block-ref-admin.js the way a browser does: two classic scripts
// run one after the other in one global scope, sharing nothing but the global object (window). The scripts are
// run with vm.runInContext, so portal.js's top-level `const Portal` is a lexical binding and not a property of
// the global object, exactly as in a page. Used by tests/test_portal_global.py.
// usage: node portal_global_harness.js <portal.js> <block-ref-admin.js>
'use strict';
const fs = require('fs');
const vm = require('vm');
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

class N {
  constructor(tag) { this.tagName = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this.disabled = false; this.style = {}; this.className = ''; }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  async fire(t, ev) { for (const f of (this.listeners[t] || [])) await f(ev || {}); }
  set textContent(v) { this.children = [{ tagName: '#text', text: String(v) }]; }
  get textContent() { return this.children.map(c => c.tagName === '#text' ? c.text : c.textContent).join(''); }
}

(async () => {
  const els = { 'block-ref-input': new N('INPUT'), 'block-ref-go': new N('BUTTON'), 'block-ref-result': new N('DIV') };
  const fetchCalls = [];
  const ctx = {
    document: {
      readyState: 'complete',
      head: new N('HEAD'), body: new N('BODY'),
      getElementById: id => els[id] || null,
      createElement: t => new N(String(t).toUpperCase()),
      addEventListener() {}, querySelector: () => null, querySelectorAll: () => [],
    },
    location: { protocol: 'https:', host: 'portal.test', pathname: '/admin', href: 'https://portal.test/admin' },
    localStorage: { getItem: () => null, setItem() {} },
    navigator: {},
    setTimeout: () => 0, setInterval: () => 0, clearTimeout() {}, clearInterval() {},
    console,
    fetch: async (url, opts) => { fetchCalls.push({ url, opts }); return { ok: false, status: 404, json: async () => ({}) }; },
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'portal.js' });
  check('portal.js sets window.Portal', ctx.Portal !== undefined && typeof ctx.Portal === 'object' && typeof ctx.Portal.fetch === 'function' && typeof ctx.Portal.toast === 'function',
        'typeof window.Portal = ' + typeof ctx.Portal);
  check('window.Portal is the Portal the page scripts name directly', vm.runInContext('window.Portal === Portal', ctx));
  vm.runInContext(fs.readFileSync(process.argv[3], 'utf8'), ctx, { filename: 'block-ref-admin.js' });
  els['block-ref-input'].value = 'abcd-efgh';
  await els['block-ref-go'].fire('click');
  const text = els['block-ref-result'].textContent;
  check('the lookup reaches Portal.fetch (credentials added, route and reference right)',
        fetchCalls.length === 1 && fetchCalls[0].url === '/api/admin/blocks/ref/abcd-efgh'
        && fetchCalls[0].opts && fetchCalls[0].opts.credentials === 'same-origin', JSON.stringify(fetchCalls));
  check('the lookup does not answer "The lookup failed."', !text.includes('The lookup failed.') && text.includes('No event found'), text);
  console.log(results.map(r => 'RESULT ' + JSON.stringify(r)).join('\n'));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'the harness ran', ok: false, detail: String(e && e.stack || e) })); });

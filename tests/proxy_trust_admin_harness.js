// Loads static/js/proxy-trust-admin.js as a classic script in a vm context with a tiny fake DOM and a fake Portal,
// and drives the list, the question, the confirm guards and the PUT. No browser: layout is not covered.
// usage: node proxy_trust_admin_harness.js <proxy-trust-admin.js>
'use strict';
const fs = require('fs');
const vm = require('vm');
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

class N {
  constructor(tag) { this.tagName = String(tag).toUpperCase(); this.children = []; this.attrs = {}; this.listeners = {}; this.style = {}; this.className = ''; this.innerHTMLWrites = 0; }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  async fire(t, ev) { for (const f of (this.listeners[t] || [])) await f(ev || {}); }
  set innerHTML(v) { this.innerHTMLWrites++; }
  set textContent(v) { this.children = [{ tagName: '#text', text: String(v) }]; }
  get textContent() { return this.children.map(c => c.tagName === '#text' ? c.text : c.textContent).join(''); }
  find(pred, out = []) { if (pred(this)) out.push(this); for (const c of this.children) if (c.find) c.find(pred, out); return out; }
}
const buttons = (n, label) => n.find(e => e.tagName === 'BUTTON' && (label === undefined || e.textContent === label));

(async () => {
  const els = { 'proxy-trust-card': new N('DIV'), 'proxy-trust-body': new N('TBODY'), 'proxy-trust-note': new N('P') };
  els['proxy-trust-card'].style.display = 'none';
  let clock = 1000000;
  const calls = [], toasts = [];
  let rows = [], putStatus = 200, release = null;
  const body = els['proxy-trust-body'];
  const ctx = {
    document: { readyState: 'complete', getElementById: id => els[id] || null, createElement: t => new N(t), addEventListener() {} },
    Date: class extends Date { static now() { return clock; } },
    Portal: {
      toast: (m, k) => toasts.push([m, k]),
      fetch: async (url, opts) => {
        opts = opts || {};
        calls.push({ url, method: opts.method || 'GET', body: opts.body });
        if (!opts.method) return { ok: true, status: 200, json: async () => ({ connections: rows }) };
        if (release) await new Promise(r => { release = r; });
        return { ok: putStatus === 200, status: putStatus, json: async () => (putStatus === 200 ? { trusted: true } : { error: 'Connection not found' }) };
      },
    },
    console,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  const src = fs.readFileSync(process.argv[2], 'utf8');
  rows = [
    { id: 'a1', name: '<img src=x onerror=alert(1)>', type: 'http', owner: 'zoe', shares: 2, browser_mode: false, trusted: false, host: 'secret.internal', config: { auth_header: 'Bearer SECRET' } },
    { id: 'b2', name: 'Wiki', type: 'http', owner: 'amy', shares: 1, browser_mode: false, trusted: true },
    { id: 'c3', name: 'Surf', type: 'http', owner: 'bob', shares: 3, browser_mode: true, trusted: false },
    { id: 'd4', name: 'Private', type: 'http', owner: 'cy', shares: 0, browser_mode: false, trusted: false },
  ];
  vm.runInContext(src, ctx, { filename: 'proxy-trust-admin.js' });
  await new Promise(r => setImmediate(r)); await new Promise(r => setImmediate(r));
  check('the card shows itself when the list loads', els['proxy-trust-card'].style.display === '', els['proxy-trust-card'].style.display);
  const text = body.textContent;
  check('only connections that are shared are listed (three of four)', text.includes('Wiki') && text.includes('Surf') && text.includes('<img src=x onerror=alert(1)>') && !text.includes('Private'), text);
  check('the connection name is text, never markup', body.find(e => e.innerHTMLWrites > 0).length === 0 && body.find(e => e.tagName === 'IMG').length === 0);
  check('no host, port or stored secret is shown even if the list carried one', !/secret\.internal|SECRET|auth_header/.test(text), text);
  check('an untrusted row offers Trust, a trusted one Remove trust, a browser-mode one neither',
        buttons(body, 'Trust').length === 1 && buttons(body, 'Remove trust').length === 1 && text.includes('Never (browser mode)'));
  check('the list is the only call so far', calls.length === 1 && calls[0].url === '/api/admin/proxy-trust-connections' && calls[0].method === 'GET', JSON.stringify(calls));

  // ---- Trust asks first, on its own row, with the confirm button somewhere else than the opening click
  const trustBtn = buttons(body, 'Trust')[0];
  await trustBtn.fire('click', { detail: 1 });
  const trs = body.children;
  const confirmRows = trs.filter(r => r.className === 'proxy-trust-confirm-row');
  check('Trust opens a question on its own row and sends nothing yet', confirmRows.length === 1 && calls.length === 1);
  check('the question names the connection and its owner and says what trusting means',
        /zoe/.test(confirmRows[0].textContent) && /run on the portal's own address/.test(confirmRows[0].textContent));
  check('the Trust button is gone from where it was clicked (the list was redrawn, the confirm is in another row)',
        !trs.some(r => r.className !== 'proxy-trust-confirm-row' && r.find(e => e.tagName === 'BUTTON' && /^Yes/.test(e.textContent)).length)
        && buttons(confirmRows[0], 'Yes, trust it').length === 1);
  let yes = buttons(body, 'Yes, trust it')[0];
  await yes.fire('click', { detail: 1 });
  check('a confirm click right after the question opened is ignored', calls.length === 1);
  clock += 700;
  await yes.fire('click', { detail: 2 });
  check('the second click of a double click is ignored', calls.length === 1);
  release = () => {};     // the PUT stays in flight until released
  const first = yes.fire('click', { detail: 1 });
  await new Promise(r => setImmediate(r));
  const second = yes.fire('click', { detail: 1 });
  await new Promise(r => setImmediate(r));
  check('while the request is in flight the confirm button is disabled and a second click sends nothing',
        calls.filter(c => c.method === 'PUT').length === 1 && buttons(body, 'Yes, trust it').every(b => b.attrs.disabled === 'disabled')
        && buttons(body, 'Remove trust').every(b => b.attrs.disabled === 'disabled'));
  await buttons(body, 'Remove trust')[0].fire('click', { detail: 1 });
  check('another action cannot be asked while one is in flight', body.children.filter(r => r.className === 'proxy-trust-confirm-row').length === 1);
  release(); await first; await second;
  const puts = calls.filter(c => c.method === 'PUT');
  check('exactly one PUT, to the connection\'s own route, trusted true', puts.length === 1 && puts[0].url === '/api/admin/connections/a1/proxy-trust' && puts[0].body === '{"trusted":true}', JSON.stringify(puts));
  check('the answer is toasted and the list is read again', toasts.some(t => t[1] === 'success') && calls[calls.length - 1].method === 'GET');

  // ---- Remove trust, and a refused change
  rows[1].trusted = false; rows[0].trusted = true;
  await new Promise(r => setImmediate(r));
  const ctl = ctx.ProxyTrustAdmin.mount({ tbody: new N('TBODY'), note: new N('P') }, async (kind, id, t) => {
    calls.push({ url: kind + ':' + id, method: 'API', body: String(t) });
    return kind === 'list' ? { ok: true, data: { connections: rows } } : { ok: false, data: { error: 'Connection not found' } };
  });
  await ctl.load();
  ctl.ask('a1', 'untrust');
  clock += 700;
  await ctl.run({ detail: 1 });
  check('Remove trust sends trusted false', calls.some(c => c.url === 'set:a1' && c.body === 'false'));
  check('a refusal is toasted as an error with the reason', toasts.some(t => t[1] === 'error' && /Connection not found/.test(t[0])), JSON.stringify(toasts));
  check('the source has no inline handler and writes no markup', !/onclick|innerHTML|insertAdjacentHTML|document\.write/.test(src.replace(/\/\*[\s\S]*?\*\//g, '')));

  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness', ok: false, detail: String(e && e.stack) })); });

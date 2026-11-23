// Runs static/js/announce.js under Node against a small fake document. Used by tests/test_announce_client.py.
// usage: node announce_harness.js <announce.js>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const A = require(process.argv[2]);
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

class Node_ {
  constructor(tag) { this.tagName = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.className = ''; this._text = null; }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { this.children.push(c); return c; }
  insertBefore(c, ref) { const i = ref ? this.children.indexOf(ref) : -1; if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  click() { (this.listeners.click || []).forEach(f => f({})); }
  set textContent(v) { this.children = [{ tagName: '#text', text: String(v) }]; }
  get textContent() { return this.children.map(c => c.tagName === '#text' ? c.text : c.textContent).join(''); }
  set innerHTML(v) { throw new Error('innerHTML must never be assigned'); }
  set outerHTML(v) { throw new Error('outerHTML must never be assigned'); }
  insertAdjacentHTML() { throw new Error('insertAdjacentHTML must never be used'); }
}
function makeDoc() {
  const created = [];
  const doc = {
    created,
    head: new Node_('head'), body: new Node_('body'), hidden: false, listeners: {},
    createElement(t) { const n = new Node_(t.toUpperCase()); created.push(n); return n; },
    createTextNode(t) { return { tagName: '#text', text: String(t) }; },
    getElementById(id) { return find(doc.body, n => n.id === id); },
    addEventListener(t, f) { (doc.listeners[t] = doc.listeners[t] || []).push(f); },
    readyState: 'complete',
  };
  doc.body.classList = { contains: () => false };
  return doc;
}
function find(n, pred) { if (!n || !n.children) return null; for (const c of n.children) { if (pred(c)) return c; const r = find(c, pred); if (r) return r; } return null; }
function all(n, pred, out) { out = out || []; (n.children || []).forEach(c => { if (pred(c)) out.push(c); all(c, pred, out); }); return out; }
function tags(doc) { return doc.created.map(n => n.tagName); }
function render(body) { const doc = makeDoc(); const box = new Node_('DIV'); A.renderBody(doc, body, box); return { doc, box }; }
function store(init) { const m = new Map(Object.entries(init || {})); return { getItem: k => m.has(k) ? m.get(k) : null, setItem: (k, v) => m.set(k, String(v)), _m: m }; }

(async () => {
  // ---- hostile text stays text ------------------------------------------------------------------------------
  let r = render('Storage is down <script>alert(1)</script> and <img src=x onerror=alert(1)> <b>x</b>');
  check('a script tag and an image with a handler are text, no such element is made',
        !tags(r.doc).includes('SCRIPT') && !tags(r.doc).includes('IMG') && !tags(r.doc).includes('B')
        && r.box.textContent === 'Storage is down <script>alert(1)</script> and <img src=x onerror=alert(1)> <b>x</b>', r.box.textContent);
  r = render('[click](javascript:alert(1)) and [again](JaVaScRiPt:alert(2)) and [d](data:text/html,<b>) and [v](vbscript:x) and [f](file:///etc/passwd)');
  check('javascript:, data:, vbscript: and file: links are not links (the text is shown as written)',
        !tags(r.doc).includes('A') && r.box.textContent.includes('[click](javascript:alert(1))'), r.box.textContent);
  r = render('[tab](java\tscript:alert(1)) [nl](&#106;avascript:alert(1)) [sp]( javascript:alert(1))');
  check('obfuscated schemes do not become links', !tags(r.doc).includes('A'), tags(r.doc).join());
  r = render('see [the status page](https://status.example.org/x?a=1&b=2) or http://example.com/path, then https://example.org.');
  const links = all(r.box, n => n.tagName === 'A');
  check('http and https links become links with rel noopener noreferrer and a new tab',
        links.length === 3 && links.every(a => a.attrs.rel === 'noopener noreferrer' && a.attrs.target === '_blank'
          && /^https?:\/\//.test(a.attrs.href)), JSON.stringify(links.map(a => a.attrs)));
  check('a bare link loses the punctuation that ends the sentence',
        links[1].attrs.href === 'http://example.com/path' && links[2].attrs.href === 'https://example.org/'
        && links[2].textContent === 'https://example.org', JSON.stringify(links.map(a => [a.attrs.href, a.textContent])));
  check('a link label is text', links[0].textContent === 'the status page');
  r = render('[<b>x</b>](https://example.com)');
  const lab = all(r.box, n => n.tagName === 'A')[0];
  check('markup in a link label is text', lab && lab.textContent === '<b>x</b>' && !tags(r.doc).includes('B'));

  // ---- the safe subset -----------------------------------------------------------------------------------------------
  r = render('This is **bold**, *italic*, `code *not italic*` and ***both***.\nSecond line\n\nFourth');
  check('bold, italic and inline code', all(r.box, n => n.tagName === 'STRONG').length >= 1 && all(r.box, n => n.tagName === 'EM').length >= 1
        && all(r.box, n => n.tagName === 'CODE')[0].textContent === 'code *not italic*', tags(r.doc).join());
  check('line breaks become br elements, one per line break', all(r.box, n => n.tagName === 'BR').length === 3);
  r = render('2 * 3 * 4 and **unclosed and `open and [x](');
  check('markers that do not close stay literal text', r.box.textContent === '2 * 3 * 4 and **unclosed and `open and [x](');
  r = render('**a *b `c` d* e**');
  check('nesting works to a bounded depth and keeps the text', r.box.textContent === 'a b c d e');
  let deep = 'x'; for (let i = 0; i < 400; i++) deep = '**' + deep + '**';
  const t0 = Date.now(); r = render(deep);
  check('deeply nested markers do not run away', Date.now() - t0 < 1000);
  const t1 = Date.now(); render('*'.repeat(5000) + 'a' + '['.repeat(2000) + '`'.repeat(2000));
  check('long runs of markers are linear enough (under a second)', Date.now() - t1 < 1000);
  check('the null and number cases are text', render(null).box.textContent === '' && render(12).box.textContent === '12');
  check('safeUrl accepts http and https only', A.safeUrl('https://a.example/') && A.safeUrl('http://a.example')
        && !A.safeUrl('ftp://a.example') && !A.safeUrl('//a.example') && !A.safeUrl('/relative') && !A.safeUrl('mailto:a@b.c')
        && !A.safeUrl('javascript:alert(1)') && !A.safeUrl(null) && !A.safeUrl('x'.repeat(3000)));

  // ---- dismissal by id and last change ----------------------------------------------------------------------------------------
  const a1 = { id: 1, level: 'outage', body: 'one', updated_at: '2026-11-22T10:00:00Z' };
  const a2 = { id: 2, level: 'info', body: 'two', updated_at: '2026-11-22T11:00:00Z' };
  let map = {}; map[String(a1.id)] = a1.updated_at;
  check('a dismissed announcement is not shown', A.visible([a1, a2], map).map(a => a.id).join() === '2');
  check('after an edit (new updated_at) it shows again', A.visible([{ ...a1, updated_at: '2026-11-22T12:00:00Z' }, a2], map).map(a => a.id).join() === '1,2');
  check('a dismissal of another announcement does not hide this one', A.visible([a2], { '1': a1.updated_at }).length === 1);
  check('entries for announcements that are gone are dropped', JSON.stringify(A.pruneDismissed({ '1': 'x', '9': 'y' }, [a1])) === '{"1":"x"}');
  const bad = store({ [A.STORE_KEY]: '[1,2' });
  check('garbled storage reads as nothing dismissed', JSON.stringify(A.readDismissed(bad)) === '{}'
        && JSON.stringify(A.readDismissed(store({ [A.STORE_KEY]: '[1]' }))) === '{}' && JSON.stringify(A.readDismissed(store())) === '{}');
  const proto = A.readDismissed(store({ [A.STORE_KEY]: '{"__proto__":{"x":1},"constructor":"y"}' }));
  check('keys such as __proto__ and constructor are harmless', !A.isDismissed(proto, { id: 'toString', updated_at: 'x' })
        && !A.isDismissed({}, { id: 'constructor', updated_at: 'x' }));

  // ---- banners ---------------------------------------------------------------------------------------------------------------------
  const doc = makeDoc(); const box = new Node_('DIV'); const dismissed = [];
  A.renderBanners(doc, box, [a1, { id: 3, level: 'weird<script>', body: 'three', updated_at: 'u' }, a2], { '2': a2.updated_at }, a => dismissed.push(a.id));
  const rows = box.children;
  check('one banner per undismissed announcement, the level on the class and the role',
        rows.length === 2 && rows[0].className === 'announce announce-outage' && rows[0].attrs.role === 'alert'
        && rows[1].className === 'announce announce-info' && rows[1].attrs.role === 'status', JSON.stringify(rows.map(x => x.className)));
  const btn = all(rows[0], n => n.tagName === 'BUTTON')[0];
  btn.click();
  check('the Dismiss button is a type=button with a label and calls back with the announcement',
        btn.attrs.type === 'button' && btn.textContent === 'Dismiss' && btn.attrs['aria-label'] && dismissed.join() === '1');
  check('no markup is ever built from text: innerHTML was never assigned (the fake throws if it is)', true);

  // ---- the page runner -------------------------------------------------------------------------------------------------------------------
  async function runPage(pathname, payloads, st, bodyClassLogin) {
    const d = makeDoc();
    if (bodyClassLogin) d.body.classList = { contains: c => c === 'login-page' };
    d.body.appendChild(new Node_('MAIN'));
    const calls = [];
    const win = {
      document: d, location: { pathname }, localStorage: st,
      fetch: (url, opts) => { calls.push(url); const p = payloads.shift(); return Promise.resolve(p === 401 ? { ok: false, status: 401, json: async () => ({}) } : { ok: true, json: async () => p }); },
      setInterval: () => 0,
    };
    const h = A.start(win, '/api/announcements');
    await new Promise(res => setTimeout(res, 20));
    return { d, win, h, calls, box: d.getElementById('portal-announcements') };
  }
  const st = store();
  let p = await runPage('/dashboard', [{ announcements: [a1, a2] }], st);
  check('start: the banners are the first thing in the body, in normal flow',
        p.box && p.d.body.children[0] === p.box && p.box.className === '' && p.box.children.length === 2, p.box && p.box.className);
  all(p.box, n => n.tagName === 'BUTTON')[0].click();
  check('dismissing removes that banner and remembers id and last change',
        p.box.children.length === 1 && JSON.parse(st.getItem(A.STORE_KEY))['1'] === a1.updated_at, st.getItem(A.STORE_KEY));
  await p.h.load.call ? null : null;
  p = await runPage('/chat', [{ announcements: [a1, a2] }], st);
  check('a reload of another page does not show the dismissed one again', p.box.children.length === 1 && p.box.children[0].attrs['data-announcement-id'] === '2');
  p = await runPage('/chat', [{ announcements: [{ ...a1, body: 'one, edited', updated_at: '2026-11-22T13:00:00Z' }, a2] }], st);
  check('an edited announcement shows again', p.box.children.length === 2);
  p = await runPage('/chat', [{ announcements: [a2] }], st);
  check('an announcement that ended is gone from the page and from the remembered map',
        p.box.children.length === 1 && !('1' in JSON.parse(st.getItem(A.STORE_KEY))));
  p = await runPage('/dashboard', [401], store());
  check('signed out (401): nothing is added to the page', p.box === null && p.d.body.children.length === 1);
  p = await runPage('/dashboard', [{ announcements: [] }], store());
  check('no announcements: nothing is added to the page', p.box === null);
  p = await runPage('/terminal/connect', [{ announcements: [a1] }], store());
  check('on a full-height application page the banner floats (overlay class)', p.box.className === 'announce-overlay');
  p = await runPage('/login', [{ announcements: [a1] }], store(), true);
  check('on the sign-in page the banner floats too', p.box.className === 'announce-overlay');
  for (const path of ['/chat', '/watch/12']) {
    p = await runPage(path, [{ announcements: [a1] }], store());
    check('on ' + path + ' (the page cannot scroll) the banner floats, so it cannot push the input or the controls out of view',
          p.box.className === 'announce-overlay', p.box.className);
  }
  p = await runPage('/dashboard', [{ announcements: [a1] }], store());
  const css = p.d.created.filter(n => n.tagName === 'STYLE').map(n => n.textContent).join('');
  check('a floating banner is capped at 40 percent of the viewport and scrolls inside itself (a long text cannot cover the sign-in form)',
        /#portal-announcements\.announce-overlay\{[^}]*max-height:40vh[^}]*overflow-y:auto/.test(css), css);

  // the poll: nothing while the tab is hidden, one request when it shows, and no more after a 401
  {
    const d = makeDoc(); d.body.appendChild(new Node_('MAIN')); d.hidden = true;
    const calls = []; let timer = null, cleared = 0;
    const win = { document: d, location: { pathname: '/dashboard' }, localStorage: store(),
      fetch: (url) => { calls.push(url); return Promise.resolve({ ok: true, json: async () => ({ announcements: [a1] }) }); },
      setInterval: (f) => { timer = f; return 7; }, clearInterval: (id) => { if (id === 7) cleared++; } };
    A.start(win, '/api/announcements');
    await new Promise(res => setTimeout(res, 10));
    timer();
    await new Promise(res => setTimeout(res, 10));
    check('a hidden tab makes no request, neither at the start nor on the timer', calls.length === 0, calls.length);
    d.hidden = false;
    (d.listeners.visibilitychange || []).forEach(f => f());
    await new Promise(res => setTimeout(res, 10));
    check('a tab that becomes visible asks once', calls.length === 1, calls.length);
  }
  {
    const d = makeDoc(); d.body.appendChild(new Node_('MAIN'));
    const calls = []; let timer = null, cleared = 0;
    const win = { document: d, location: { pathname: '/dashboard' }, localStorage: store(),
      fetch: (url) => { calls.push(url); return Promise.resolve({ ok: false, status: 401, json: async () => ({}) }); },
      setInterval: (f) => { timer = f; return 7; }, clearInterval: (id) => { if (id === 7) cleared++; } };
    A.start(win, '/api/announcements');
    await new Promise(res => setTimeout(res, 10));
    timer();
    (d.listeners.visibilitychange || []).forEach(f => f());
    await new Promise(res => setTimeout(res, 10));
    check('after a 401 the poll stops: no timer tick and no visibility change asks again, and the timer is cleared',
          calls.length === 1 && cleared >= 1, JSON.stringify({ calls: calls.length, cleared }));
  }
  const pub = store({ [A.STORE_KEY]: JSON.stringify({ '7': 'keep me' }) });
  const d2 = makeDoc(); d2.body.appendChild(new Node_('MAIN'));
  A.start({ document: d2, location: { pathname: '/login' }, localStorage: pub, setInterval: () => 0,
            fetch: () => Promise.resolve({ ok: true, json: async () => ({ announcements: [a1] }) }) }, '/api/announcements/public');
  await new Promise(res => setTimeout(res, 20));
  check('the sign-in list does not make the browser forget what a member dismissed', JSON.parse(pub.getItem(A.STORE_KEY))['7'] === 'keep me');

  console.log(results.map(x => 'RESULT ' + JSON.stringify(x)).join('\n'));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness crashed', ok: false, detail: e.stack })); });

// Runs openStream of static/streams.html (the embedded viewer) under Node against a fake page and a fake fetch.
// No browser: the real overlay, player and chat are not covered.
// Used by tests/test_streams_page.py.
//
// usage: node streams_page_harness.js <path to streams.html>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(process.argv[2], 'utf8');
function fn(name) {
  let a = html.indexOf('async function ' + name + '(');
  if (a < 0) a = html.indexOf('function ' + name + '(');
  if (a < 0) throw new Error('function not found: ' + name);
  let i = html.indexOf('{', html.indexOf(')', a));
  let depth = 0;
  for (; i < html.length; i++) {
    if (html[i] === '{') depth++;
    else if (html[i] === '}' && --depth === 0) return html.slice(a, i + 1);
  }
  throw new Error('unbalanced: ' + name);
}
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }
async function withDeadline(name, f, ms) {
  let timer;
  const late = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('no answer within ' + (ms || 5000) + ' ms')), ms || 5000); });
  try { await Promise.race([f(), late]); } catch (e) { check(name + ' (did not finish)', false, e && e.message); } finally { clearTimeout(timer); }
}

function world(answer) {
  const toasts = [];
  const opened = [];
  const el = () => ({ style: {}, textContent: '', innerHTML: '', classList: { add: (c) => opened.push(c) }, parentElement: { innerHTML: '' }, value: 'normal' });
  const sandbox = {
    Portal: { toast: (t, k) => toasts.push([t, k]) },
    document: { getElementById: () => el(), querySelector: () => el() },
    fetch: () => Promise.resolve(answer),
    console: { error() {}, log() {} },
    currentStream: null, hlsPlayer: null, Hls: { isSupported: () => false },
    showViewerInfo() {}, connectChat() {},
  };
  vm.createContext(sandbox);
  let consts = '';
  const m = html.match(/const BANNED_STREAM_TEXT = [^\n]*;/);
  if (m) consts = m[0];
  vm.runInContext(consts + '\n' + fn('openStream') + '\nthis.openStream = openStream;', sandbox);
  return { sandbox, toasts, opened };
}
function reply(status, body) { return { status, ok: status >= 200 && status < 300, json: async () => body }; }

(async () => {
  await withDeadline('banned', async () => {
    const w = world(reply(403, { error: 'banned', banned: true, message: 'You are banned from this stream' }));
    await w.sandbox.openStream('abc', 1);
    const t = w.toasts.map(x => x[0]);
    check('a 403 banned answer shows the banned explanation (the watch page wording), not a generic failure',
      t.length === 1 && t[0] === 'You are banned from this stream by its owner. The ban applies to watching while signed in.' && w.toasts[0][1] === 'error', JSON.stringify(w.toasts));
    check('the viewer is not opened for a banned member', w.opened.length === 0 && w.sandbox.currentStream === null);
  });
  await withDeadline('not found', async () => {
    const w = world(reply(404, { error: 'Stream not found' }));
    await w.sandbox.openStream('abc', 1);
    check('a 404 still says Stream not found', w.toasts.length === 1 && w.toasts[0][0] === 'Stream not found', JSON.stringify(w.toasts));
  });
  await withDeadline('other 403', async () => {
    const w = world(reply(403, { error: 'Forbidden' }));
    await w.sandbox.openStream('abc', 1);
    check('a 403 that is not a ban is not described as one', w.toasts.length === 1 && w.toasts[0][0] === 'Stream not found', JSON.stringify(w.toasts));
  });
  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness crashed', ok: false, detail: e && e.stack })); });

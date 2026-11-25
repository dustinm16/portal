"""Mobile key bar for the web terminal.

Static checks on static/terminal.html and the scripts, then the real
terminal-keybar.js and terminal.js run under Node against a small fake DOM,
a fake xterm Terminal and a fake WebSocket, using the key bar buttons parsed
from the real terminal.html. Node is needed for the second half; without it
that part is reported as skipped.

Run: venv/bin/python tests/test_keybar.py
"""

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
HTML = (STATIC / "terminal.html").read_text()
TERMINAL_JS = (STATIC / "js" / "terminal.js").read_text()

# ---- static: markup, versions, defaults ------------------------------------
assert re.search(r'/static/js/terminal\.js\?v=(\d+)', HTML), "terminal.js must carry a version"
assert int(re.search(r'/static/js/terminal\.js\?v=(\d+)', HTML).group(1)) >= 4
assert "/static/js/terminal-keybar.js?v=2" in HTML
assert "/static/js/hostkey.js?v=1" in HTML, "the host-key prompt must keep loading"
# the helpers load before the terminal script that uses them
assert HTML.index("terminal-keybar.js") < HTML.index("/static/js/terminal.js")
assert HTML.index("hostkey.js") < HTML.index("/static/js/terminal.js")

# the bar is hidden unless the script turns it on
assert re.search(r"\.keybar\s*\{[^}]*display:\s*none", HTML), "bar must be hidden by default"
assert "body.keybar-on .keybar" in HTML
assert 'class="keybar"' in HTML and 'id="keybar-toggle"' in HTML

# xterm and its fit addon come from the vendored copies (no script from another host), plus our own scripts
srcs = re.findall(r'<script src="([^"]+)"', HTML)
external = [s for s in srcs if s.startswith("http") or s.startswith("//")]
assert external == [], external
assert "/static/vendor/xterm/xterm.js?v=5.3.0" in srcs and "/static/vendor/xterm-addon-fit/xterm-addon-fit.js?v=0.8.0" in srcs, srcs

# key bar buttons: the keys the plan lists, no inline handlers on them
bar = re.search(r'<div class="keybar".*?</div>', HTML, re.S).group(0)
buttons = re.findall(r"<button\b[^>]*>.*?</button>", bar, re.S)
assert "onclick" not in bar
labels = [re.sub(r"<[^>]+>", "", b).strip() for b in buttons]
for needed in ("Esc", "Tab", "Ctrl", "Alt", "|", "~", "/", "Paste", "A-", "A+"):
    assert needed in labels, (needed, labels)
for direction in ("left", "right", "up", "down"):
    assert f'data-key="{direction}"' in bar, direction

# every page that loads terminal.js carries the bumped version and the helper
for page in STATIC.glob("*.html"):
    text = page.read_text()
    if "js/terminal.js" in text:
        assert "js/terminal.js?v=7" in text, page.name
        assert "js/terminal-keybar.js?v=2" in text, page.name

# storage access is guarded, no external code, host-key flow untouched
assert TERMINAL_JS.count("localStorage") == 2
assert re.search(r"try \{ return window\.localStorage\.getItem", TERMINAL_JS)
assert re.search(r"try \{ window\.localStorage\.setItem", TERMINAL_JS)
assert "HostKey.prompt(data, { onAccepted: () => reconnect() })" in TERMINAL_JS
assert "http" not in (STATIC / "js" / "terminal-keybar.js").read_text()

# ---- dynamic: run the real scripts under Node -------------------------------
node = shutil.which("node")
if not node:
    print("ok (static only; node not found, dynamic checks skipped)")
    sys.exit(0)

HARNESS = r'''
const fs = require('fs');
const vm = require('vm');
const html = fs.readFileSync(process.argv[2], 'utf8');
const keysSrc = fs.readFileSync(process.argv[3], 'utf8');
const termSrc = fs.readFileSync(process.argv[4], 'utf8');
const results = [];
function check(name, ok, detail) { results.push([name, !!ok, detail === undefined ? '' : String(detail)]); }

class El {
  constructor(id) { this.id = id; this.dataset = {}; this.attrs = {}; this.handlers = {}; this.hidden = false;
    this.value = ''; this.textContent = ''; this.disabled = false; this.children = []; this.focused = 0;
    const set = new Set(); this._cls = set;
    this.classList = { toggle: (c, on) => { (on === undefined ? !set.has(c) : on) ? set.add(c) : set.delete(c); },
                       contains: c => set.has(c) }; }
  addEventListener(t, fn) { (this.handlers[t] = this.handlers[t] || []).push(fn); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  closest() { return this; }
  focus() { this.focused++; }
  querySelectorAll(sel) { return sel === '[data-mod]' ? this.children.filter(c => c.dataset.mod) : []; }
  fire(t, ev) { (this.handlers[t] || []).forEach(h => h(Object.assign({ target: this, preventDefault() {} }, ev))); }
}

function build(opts) {
  const els = {};
  for (const id of ['keybar', 'keybar-toggle', 'paste-dialog', 'paste-text', 'paste-hint', 'paste-send',
                    'paste-cancel', 'terminal-container', 'connection-status', 'status-text']) els[id] = new El(id);
  els['paste-dialog'].hidden = true;
  els['paste-send'].disabled = true;
  els['keybar-toggle'].attrs['aria-pressed'] = 'false';
  // buttons parsed from the real markup
  const bar = html.match(/<div class="keybar".*?<\/div>/s)[0];
  for (const m of bar.matchAll(/<button\b([^>]*)>(.*?)<\/button>/gs)) {
    const b = new El(''); b.label = m[2].replace(/<[^>]+>/g, '').trim();
    for (const a of m[1].matchAll(/data-([a-z-]+)="([^"]*)"/g)) b.dataset[a[1].replace(/-(.)/g, (_, c) => c.toUpperCase())] = a[2];
    if (/aria-pressed/.test(m[1])) b.attrs['aria-pressed'] = 'false';
    els['keybar'].children.push(b);
  }
  els['keybar'].querySelector = null;
  const bodyCls = new El('body');
  const store = opts.storage || {};
  const sockets = [];
  const pasted = [];
  const termListeners = [];
  const textarea = new El('xterm-helper-textarea');
  class FakeTerminal {
    constructor(o) { this.options = Object.assign({}, o); this.cols = 80; this.rows = 24; this.modes = { applicationCursorKeysMode: false }; }
    loadAddon() {} open() {} clear() {} write() {} writeln() {}
    get textarea() { return textarea; }
    focus() { this.focusCalls = (this.focusCalls || 0) + 1; ctx.document.activeElement = textarea; }
    onData(cb) { termListeners.push(cb); return { dispose() { const i = termListeners.indexOf(cb); if (i >= 0) termListeners.splice(i, 1); } }; }
    paste(t) { pasted.push(t); termListeners.slice().forEach(cb => cb(t)); }
  }
  class FakeWS { constructor(u) { this.url = u; this.readyState = 1; this.sent = []; sockets.push(this); }
    send(d) { this.sent.push(JSON.parse(d)); } close() {} }
  FakeWS.OPEN = 1;
  const style = { props: {}, setProperty(k, v) { this.props[k] = v; } };
  const win = {
    matchMedia: q => ({ matches: !!opts.coarse && q === '(pointer: coarse)' }),
    addEventListener() {},
    location: { replaced: [], replace(u) { this.replaced.push(u); } },
    visualViewport: opts.noViewport ? undefined : { height: 500, offsetTop: 0, scale: 1, addEventListener() {} },
    localStorage: opts.brokenStorage ? { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } }
      : { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } },
  };
  const ctx = {
    window: win, console, setTimeout, clearTimeout, JSON, Array, Math, Number, isFinite, String,
    document: {
      getElementById: id => els[id] || null,
      querySelector: sel => { const m = sel.match(/\[data-mod="(\w+)"\]/); return m ? els['keybar'].children.find(c => c.dataset.mod === m[1]) : null; },
      body: bodyCls, documentElement: { style }, activeElement: null,
      addEventListener() {},
    },
    Terminal: FakeTerminal, FitAddon: { FitAddon: class { fit() {} } },
    WebSocket: FakeWS,
    Portal: { getWebSocketUrl: p => 'wss://x' + p },
    HostKey: { prompt() {} },
    navigator: opts.clipboard === undefined ? {} : { clipboard: opts.clipboard },
  };
  ctx.window.navigator = ctx.navigator;
  win.window = win;
  vm.createContext(ctx);
  // the page scripts see the window members as globals
  vm.runInContext('var self = this;', ctx);
  vm.runInContext(keysSrc, ctx);
  vm.runInContext(termSrc, ctx);
  vm.runInContext("initTerminal('svc', '/ws/x');", ctx);
  const ws = sockets[0];
  const p_term_focus_calls = () => (vm.runInContext('term', ctx).focusCalls || 0);
  return { term() { return vm.runInContext('term', ctx); }, els, ctx, ws, sockets, pasted, termListeners, store, style, body: bodyCls,
           click(label) { const b = els['keybar'].children.find(c => c.label === label); if (!b) throw new Error('no button ' + label); els['keybar'].fire('click', { target: b }); },
           mousedown(label) { const b = els['keybar'].children.find(c => c.label === label); els['keybar'].fire('mousedown', { target: b }); },
           blur() { ctx.document.activeElement = null; },
           focusCalls() { return p_term_focus_calls(); },
           soft(data) { termListeners.slice().forEach(cb => cb(data)); },
           sent() { return ws.sent.filter(m => m.type === 'input').map(m => m.data); },
           async flush() { await new Promise(r => setTimeout(r, 20)); } };
}
async function main() {
  // --- default visibility ---
  let p = build({ coarse: false });
  check('desktop: bar hidden by default', !p.body.classList.contains('keybar-on'));
  p = build({ coarse: true });
  check('touch: bar shown by default', p.body.classList.contains('keybar-on'));
  p = build({ coarse: true, storage: { 'portal.terminal.keybar': '0' } });
  check('touch: stored off wins', !p.body.classList.contains('keybar-on'));
  p = build({ coarse: false, storage: { 'portal.terminal.keybar': '1' } });
  check('desktop: stored on wins', p.body.classList.contains('keybar-on'));
  p = build({ coarse: true, brokenStorage: true });
  check('blocked storage: page still starts, default applies', p.body.classList.contains('keybar-on') && !!p.ws);
  p.els['keybar-toggle'].fire('click', {});
  check('blocked storage: toggle still works', !p.body.classList.contains('keybar-on'));

  // --- toggle remembered ---
  p = build({ coarse: false });
  p.els['keybar-toggle'].fire('click', {});
  check('toggle on is stored as 1', p.store['portal.terminal.keybar'] === '1' && p.body.classList.contains('keybar-on'));
  check('toggle button reflects state', p.els['keybar-toggle'].attrs['aria-pressed'] === 'true');
  p.els['keybar-toggle'].fire('click', {});
  check('toggle off is stored as 0', p.store['portal.terminal.keybar'] === '0' && !p.body.classList.contains('keybar-on'));

  // --- keys reach the socket ---
  p = build({ coarse: true });
  p.click('Esc'); p.click('Tab');
  check('Esc and Tab', JSON.stringify(p.sent()) === JSON.stringify(['\x1b', '\t']), JSON.stringify(p.sent()));

  p = build({ coarse: true });
  p.click('Ctrl');
  check('Ctrl shows as armed', p.els['keybar'].children.find(c => c.label === 'Ctrl').attrs['aria-pressed'] === 'true');
  p.soft('c');
  p.soft('c');
  check('Ctrl then c from the soft keyboard sends 0x03, then plain c', JSON.stringify(p.sent()) === JSON.stringify(['\x03', 'c']), JSON.stringify(p.sent()));
  check('Ctrl disarms after one key', p.els['keybar'].children.find(c => c.label === 'Ctrl').attrs['aria-pressed'] === 'false');

  p = build({ coarse: true });
  p.click('Ctrl'); p.click('Ctrl'); p.soft('c');
  check('tapping Ctrl twice disarms it', JSON.stringify(p.sent()) === JSON.stringify(['c']));

  p = build({ coarse: true });
  p.click('Alt'); p.soft('x'); p.click('Alt'); p.click('Tab');
  check('Alt then x sends ESC x; Alt then Tab sends ESC Tab', JSON.stringify(p.sent()) === JSON.stringify(['\x1bx', '\x1b\t']), JSON.stringify(p.sent()));

  p = build({ coarse: true });
  p.click('Ctrl'); p.click('Alt'); p.soft('d');
  check('Ctrl and Alt together', JSON.stringify(p.sent()) === JSON.stringify(['\x1b\x04']), JSON.stringify(p.sent()));

  p = build({ coarse: true });
  p.click('|'); p.click('~'); p.click('/');
  check('symbol keys send their character', JSON.stringify(p.sent()) === JSON.stringify(['|', '~', '/']));

  // --- arrows follow the application cursor mode ---
  p = build({ coarse: true });
  const arrows = () => ['←', '↓', '↑', '→'];
  const byDir = {};
  for (const b of p.els['keybar'].children) if (b.dataset.key && ['left','right','up','down'].includes(b.dataset.key)) byDir[b.dataset.key] = b;
  const press = d => p.els['keybar'].fire('click', { target: byDir[d] });
  press('up'); press('left');
  p.term().modes.applicationCursorKeysMode = true;
  press('up'); press('left');
  check('arrows: normal mode ESC [ x, application mode ESC O x',
        JSON.stringify(p.sent()) === JSON.stringify(['\x1b[A', '\x1b[D', '\x1bOA', '\x1bOD']), JSON.stringify(p.sent()));
  p.click('Ctrl'); press('right');
  check('Ctrl with an arrow sends the modified form', p.sent().pop() === '\x1b[1;5C');

  // --- the other input listeners still see bar keys ---
  p = build({ coarse: true });
  let got = null;
  p.ctx.promptInput(true, v => { got = v; });
  p.click('/'); p.soft('a'); p.soft('\r');
  check('password prompt receives bar characters', got === '/a', got);

  // --- paste ---
  p = build({ coarse: true, clipboard: { readText: async () => 'ls -la' } });
  p.click('Paste'); await p.flush();
  check('single-line paste goes straight to term.paste', JSON.stringify(p.pasted) === JSON.stringify(['ls -la']) && p.els['paste-dialog'].hidden === true);

  p = build({ coarse: true, clipboard: { readText: async () => 'echo a\necho b\n' } });
  p.click('Paste'); await p.flush();
  check('multi-line paste asks first', p.pasted.length === 0 && p.els['paste-dialog'].hidden === false);
  check('the dialog shows the text and the line count', p.els['paste-text'].value === 'echo a\necho b\n' && p.els['paste-send'].textContent === 'Paste 2 lines', p.els['paste-send'].textContent);
  p.els['paste-cancel'].fire('click', {});
  check('cancel pastes nothing', p.pasted.length === 0 && p.els['paste-dialog'].hidden === true);
  p.click('Paste'); await p.flush();
  p.els['paste-send'].fire('click', {});
  check('confirm pastes the text', JSON.stringify(p.pasted) === JSON.stringify(['echo a\necho b\n']) && p.els['paste-dialog'].hidden === true);

  p = build({ coarse: true, clipboard: { readText: async () => { throw new Error('denied'); } } });
  p.click('Paste'); await p.flush();
  check('refused clipboard read opens the text box', p.els['paste-dialog'].hidden === false && p.els['paste-text'].value === '' && p.els['paste-send'].disabled === true);
  p.els['paste-text'].value = 'one line';
  p.els['paste-text'].fire('input', {});
  check('typing in the box enables send', p.els['paste-send'].disabled === false && p.els['paste-send'].textContent === 'Paste');
  p.els['paste-send'].fire('click', {});
  check('text box content is pasted', JSON.stringify(p.pasted) === JSON.stringify(['one line']));

  p = build({ coarse: true });   // no navigator.clipboard (Firefox readText gap)
  p.click('Paste'); await p.flush();
  check('no clipboard API opens the text box', p.els['paste-dialog'].hidden === false);

  p = build({ coarse: true, clipboard: { readText: async () => '' } });
  p.click('Paste'); await p.flush();
  check('empty clipboard does nothing', p.pasted.length === 0 && p.els['paste-dialog'].hidden === true);

  // --- pasted text is cleaned before it reaches the terminal ---
  const dirty = 'ls\x1b[201~; rm x\x03\x04\x00\x1b[31m\tok\x7f';
  const clean = 'ls; rm x[31m\tok\x7f';
  p = build({ coarse: true, clipboard: { readText: async () => dirty } });
  p.click('Paste'); await p.flush();
  check('single-line paste: end marker and C0 controls removed, tab kept', JSON.stringify(p.pasted) === JSON.stringify([clean]), JSON.stringify(p.pasted));

  p = build({ coarse: true, clipboard: { readText: async () => 'echo a\x1b[201~\x03\r\necho b\x1b\n' } });
  p.click('Paste'); await p.flush();
  check('multi-line paste: the dialog shows the cleaned text', p.els['paste-text'].value === 'echo a\r\necho b\n', JSON.stringify(p.els['paste-text'].value));
  p.els['paste-send'].fire('click', {});
  check('multi-line paste: cleaned text is pasted', JSON.stringify(p.pasted) === JSON.stringify(['echo a\r\necho b\n']), JSON.stringify(p.pasted));

  p = build({ coarse: true, clipboard: { readText: async () => { throw new Error('denied'); } } });
  p.click('Paste'); await p.flush();
  p.els['paste-text'].value = 'one\x1b[201~\x03 line\x1b[201~';   // typed or pasted into the box itself
  p.els['paste-text'].fire('input', {});
  p.els['paste-send'].fire('click', {});
  check('text box content is cleaned too', JSON.stringify(p.pasted) === JSON.stringify(['one line']), JSON.stringify(p.pasted));

  p = build({ coarse: true, clipboard: { readText: async () => '\x1b[201~\x03' } });
  p.click('Paste'); await p.flush();
  check('a paste that is only control characters does nothing', p.pasted.length === 0 && p.els['paste-dialog'].hidden === true);

  // --- sticky Ctrl/Alt are used up by key input only ---
  p = build({ coarse: true });
  p.click('Ctrl');
  p.soft('\x1b[I'); p.soft('\x1b[O'); p.soft('\x1b[24;80R'); p.soft('\x1b[?62;4c'); p.soft('\x1b]11;rgb:0000/0000/0000\x07'); p.soft('\x1b[0n');
  check('terminal reports are passed on unchanged', JSON.stringify(p.sent()) === JSON.stringify(['\x1b[I', '\x1b[O', '\x1b[24;80R', '\x1b[?62;4c', '\x1b]11;rgb:0000/0000/0000\x07', '\x1b[0n']), JSON.stringify(p.sent()));
  check('Ctrl stays armed after terminal reports', p.els['keybar'].children.find(c => c.label === 'Ctrl').attrs['aria-pressed'] === 'true');
  p.soft('c');
  check('Ctrl then applies to the next typed key', p.sent().pop() === '\x03');
  check('Ctrl is used up by that key', p.els['keybar'].children.find(c => c.label === 'Ctrl').attrs['aria-pressed'] === 'false');

  p = build({ coarse: true });
  p.click('Alt'); p.soft('\x1b[I'); p.click('Tab');
  check('Alt survives a focus report and is used by the next bar key', JSON.stringify(p.sent()) === JSON.stringify(['\x1b[I', '\x1b\t']), JSON.stringify(p.sent()));

  p = build({ coarse: true });
  p.click('Ctrl'); p.soft('\x1b[A');
  check('an arrow key still uses up Ctrl', p.sent().pop() === '\x1b[1;5A' && p.els['keybar'].children.find(c => c.label === 'Ctrl').attrs['aria-pressed'] === 'false');

  // --- a bar tap does not bring the on-screen keyboard back ---
  p = build({ coarse: true });
  let before0 = p.focusCalls();
  p.mousedown('Esc'); p.click('Esc');
  check('terminal had focus: a bar tap hands it back', p.focusCalls() === before0 + 1, p.focusCalls() - before0);

  p = build({ coarse: true });
  p.blur(); before0 = p.focusCalls();
  p.mousedown('Esc'); p.click('Esc');
  p.mousedown('Ctrl'); p.click('Ctrl');
  p.mousedown('A+'); p.click('A+');
  p.mousedown('/'); p.click('/');
  check('keyboard dismissed: bar taps do not focus the terminal', p.focusCalls() === before0, p.focusCalls() - before0);
  check('keyboard dismissed: the keys still work', JSON.stringify(p.sent()) === JSON.stringify(['\x1b', '\x1f']), JSON.stringify(p.sent()));

  p = build({ coarse: true, clipboard: { readText: async () => 'ls' } });
  p.blur(); before0 = p.focusCalls();
  p.mousedown('Paste'); p.click('Paste'); await p.flush();
  check('keyboard dismissed: Paste pastes without focusing the terminal', JSON.stringify(p.pasted) === JSON.stringify(['ls']) && p.focusCalls() === before0, p.focusCalls() - before0);

  p = build({ coarse: true, clipboard: { readText: async () => 'a\nb' } });
  p.blur(); before0 = p.focusCalls();
  p.mousedown('Paste'); p.click('Paste'); await p.flush();
  p.els['paste-send'].fire('click', {});
  p.mousedown('Paste'); p.click('Paste'); await p.flush();
  p.els['paste-cancel'].fire('click', {});
  check('keyboard dismissed: the paste dialog does not focus the terminal either', p.focusCalls() === before0, p.focusCalls() - before0);

  p = build({ coarse: true, clipboard: { readText: async () => 'a\nb' } });
  before0 = p.focusCalls();
  p.mousedown('Paste'); p.click('Paste'); await p.flush();
  p.els['paste-cancel'].fire('click', {});
  check('terminal had focus: closing the paste dialog hands it back', p.focusCalls() === before0 + 1, p.focusCalls() - before0);

  // --- font size ---
  p = build({ coarse: true });
  p.click('A+'); p.click('A+');
  check('A+ raises the font size and stores it', p.term().options.fontSize === 16 && p.store['portal.terminal.fontsize'] === '16', p.term().options.fontSize);
  for (let i = 0; i < 40; i++) p.click('A-');
  check('font size stops at the minimum', p.term().options.fontSize === 8);
  for (let i = 0; i < 60; i++) p.click('A+');
  check('font size stops at the maximum', p.term().options.fontSize === 28);
  p = build({ coarse: true, storage: { 'portal.terminal.fontsize': '19' } });
  check('stored font size is used at start', p.term().options.fontSize === 19);
  p = build({ coarse: true, storage: { 'portal.terminal.fontsize': 'junk' } });
  check('junk stored font size falls back to the default', p.term().options.fontSize === 14);

  // --- layout follows the visual viewport ---
  p = build({ coarse: true });
  check('viewport height and offset are published', p.style.props['--vv-height'] === '500px' && p.style.props['--vv-top'] === '0px', JSON.stringify(p.style.props));
  p = build({ coarse: true, noViewport: true });
  check('no visualViewport: page still starts', !!p.ws);

  // --- hiding the bar clears an armed modifier ---
  p = build({ coarse: true });
  p.click('Ctrl'); p.els['keybar-toggle'].fire('click', {}); p.soft('c');
  check('hiding the bar disarms Ctrl', JSON.stringify(p.sent()) === JSON.stringify(['c']), JSON.stringify(p.sent()));

  // --- the reconnect hint still reacts to any input, bar included ---
  p = build({ coarse: true });
  p.ws.onclose({ code: 1006 });
  const before = p.sockets.length;
  p.click('Esc');
  check('a bar key triggers the press-any-key reconnect', p.sockets.length === before + 1, p.sockets.length);

  // --- a revoked session (close code 4001) goes to the login page, no reconnect offer ---
  p = build({ coarse: true });
  const socketsBefore = p.sockets.length;
  p.ws.onclose({ code: 4001 });
  p.click('Esc');
  check('close code 4001 sends the page to /login', JSON.stringify(p.ctx.window.location.replaced) === '["/login"]', JSON.stringify(p.ctx.window.location.replaced));
  check('close code 4001 does not offer to reconnect', p.sockets.length === socketsBefore, p.sockets.length);
  p = build({ coarse: true });
  p.ws.onclose({ code: 1006 });
  check('another close code does not leave the page', p.ctx.window.location.replaced.length === 0);

  console.log('RESULTS=' + JSON.stringify(results));
}
main().catch(e => { console.log('CRASH=' + (e && e.stack || e)); process.exit(1); });
'''

# the pure helpers, called directly
PURE = r'''
const K = require(process.argv[2]);
const out = [];
const t = (n, ok, d) => out.push([n, !!ok, d === undefined ? '' : String(d)]);
t('Ctrl+c', K.applyModifiers('c', {ctrl: true}) === '\x03');
t('Ctrl+C upper case', K.applyModifiers('C', {ctrl: true}) === '\x03');
t('Ctrl+z', K.applyModifiers('z', {ctrl: true}) === '\x1a');
t('Ctrl+[ is Esc', K.applyModifiers('[', {ctrl: true}) === '\x1b');
t('Ctrl on a digit is unchanged', K.applyModifiers('5', {ctrl: true}) === '5');
t('Ctrl on Tab is Tab', K.applyModifiers('\t', {ctrl: true}) === '\t');
t('Alt+x', K.applyModifiers('x', {alt: true}) === '\x1bx');
t('Alt+Esc', K.applyModifiers('\x1b', {alt: true}) === '\x1b\x1b');
t('Alt+Backspace', K.applyModifiers('\x7f', {alt: true}) === '\x1b\x7f');
t('no modifiers: unchanged', K.applyModifiers('c', {}) === 'c' && K.applyModifiers('c', null) === 'c');
t('a word is not modified', K.applyModifiers('hello', {ctrl: true}) === 'hello');
t('a pasted escape sequence that is not an arrow is not modified', K.applyModifiers('\x1b[200~x\x1b[201~', {ctrl: true}) === '\x1b[200~x\x1b[201~');
t('astral character with Alt', K.applyModifiers('\u{1F600}', {alt: true}) === '\x1b\u{1F600}');
t('Alt+arrow', K.applyModifiers('\x1b[A', {alt: true}) === '\x1b[1;3A');
t('Ctrl+arrow in application mode', K.applyModifiers('\x1bOB', {ctrl: true}) === '\x1b[1;5B');
t('Ctrl+Alt+arrow', K.applyModifiers('\x1b[D', {ctrl: true, alt: true}) === '\x1b[1;7D');
t('arrow, normal', K.arrowSequence('up', false) === '\x1b[A' && K.arrowSequence('down', false) === '\x1b[B' && K.arrowSequence('right', false) === '\x1b[C' && K.arrowSequence('left', false) === '\x1b[D');
t('arrow, application', K.arrowSequence('up', true) === '\x1bOA' && K.arrowSequence('left', true) === '\x1bOD');
t('unknown arrow', K.arrowSequence('sideways', false) === '');
t('paste: end marker removed', K.sanitizePaste('a\x1b[201~b') === 'ab');
t('paste: tab, CR and LF kept', K.sanitizePaste('a\tb\r\nc\nd\re') === 'a\tb\r\nc\nd\re');
t('paste: other C0 controls removed', K.sanitizePaste('\x00\x01\x03\x04\x07\x08\x0b\x0c\x0e\x1a\x1b\x1f' + 'x') === 'x');
t('paste: a marker split by another marker is gone too', K.sanitizePaste('\x1b[2\x1b[201~01~') === '[201~' && K.sanitizePaste('\x1b[2\x1b[201~01~').indexOf('\x1b') < 0);
t('paste: ordinary text, unicode and DEL unchanged', K.sanitizePaste('ls -la \u00e9\u{1F600}') === 'ls -la \u00e9\u{1F600}');
t('paste: null and undefined give an empty string', K.sanitizePaste(null) === '' && K.sanitizePaste(undefined) === '');
t('report: focus in and out', K.isTerminalReport('\x1b[I') && K.isTerminalReport('\x1b[O'));
t('report: cursor position, device attributes, status, mode, size', K.isTerminalReport('\x1b[24;80R') && K.isTerminalReport('\x1b[?1;2c') && K.isTerminalReport('\x1b[>0;276;0c') && K.isTerminalReport('\x1b[0n') && K.isTerminalReport('\x1b[?2004;2$y') && K.isTerminalReport('\x1b[8;24;80t'));
t('report: OSC and DCS replies, mouse reports', K.isTerminalReport('\x1b]11;rgb:0/0/0\x07') && K.isTerminalReport('\x1b]10;rgb:f/f/f\x1b\\') && K.isTerminalReport('\x1bP1$r0m\x1b\\') && K.isTerminalReport('\x1b[<0;10;5M') && K.isTerminalReport('\x1b[M !!'));
t('report: keys are not reports', !['a', '\x1b', '\t', '\r', '\x03', '\x1b[A', '\x1bOA', '\x1b[1;5C', '\x1b[5~', '\x1b[H', '\x1bx', '\x1b[', '\x1b]', 'hello', '\x1b[200~x\x1b[201~', '', null].some(k => K.isTerminalReport(k)));
t('multi-line needs confirm', K.pasteNeedsConfirm('a\nb') && K.pasteNeedsConfirm('a\r\nb') && K.pasteNeedsConfirm('a\rb'));
t('trailing newline needs confirm', K.pasteNeedsConfirm('rm -rf x\n'));
t('single line does not', !K.pasteNeedsConfirm('ls -la') && !K.pasteNeedsConfirm('') && !K.pasteNeedsConfirm(null));
t('line count', K.countLines('a\nb\nc') === 3 && K.countLines('a\nb\n') === 2 && K.countLines('a') === 1 && K.countLines('') === 0 && K.countLines('a\r\nb') === 2);
t('visible: touch default', K.keybarVisible(null, true) === true && K.keybarVisible(null, false) === false);
t('visible: stored choice wins', K.keybarVisible('1', false) === true && K.keybarVisible('0', true) === false);
t('visible: junk stored value falls back', K.keybarVisible('x', true) === true && K.keybarVisible('x', false) === false);
t('font clamp', K.clampFontSize(3) === 8 && K.clampFontSize(99) === 28 && K.clampFontSize('16') === 16 && K.clampFontSize('x') === 14 && K.clampFontSize(null) === 8);
console.log('RESULTS=' + JSON.stringify(out));
'''


def run_node(code, *args):
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "run.js"
        script.write_text(code)
        p = subprocess.run([node, str(script), *map(str, args)], capture_output=True, text=True, timeout=60)
    line = next((l for l in p.stdout.splitlines() if l.startswith("RESULTS=")), None)
    assert line, f"node failed: {p.stdout[-800:]} {p.stderr[-800:]}"
    return json.loads(line[len("RESULTS="):])


failed = []
total = 0
for name, results in (
    ("helpers", run_node(PURE, STATIC / "js" / "terminal-keybar.js")),
    ("page", run_node(HARNESS, STATIC / "terminal.html", STATIC / "js" / "terminal-keybar.js", STATIC / "js" / "terminal.js")),
):
    for label, ok, detail in results:
        total += 1
        if not ok:
            failed.append(f"{name}: {label} ({detail})")

assert not failed, "\n".join(failed)
print(f"ok ({total} dynamic checks)")

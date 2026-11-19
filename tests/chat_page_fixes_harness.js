// Runs three functions of static/chat.html (the voice meter note, the lost-channel
// state, the room's message sending guard) under Node against a small fake page.
// Used by tests/test_chat_page_fixes.py.
//
// usage: node chat_page_fixes_harness.js <path to chat.html>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(process.argv[2], 'utf8');
function fn(name) {
  const a = html.indexOf('function ' + name + '(');
  if (a < 0) throw new Error('function not found: ' + name);
  // up to the next function declaration at the same indent (8 spaces)
  const b = html.indexOf('\n        function ', a + 10);
  const c = html.indexOf('\n        // ', a + 10);
  const end = [b, c].filter(x => x > 0).reduce((m, x) => Math.min(m, x), Infinity);
  return html.slice(a, end);
}
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

// A text node whose writes are counted (a role=status region is announced on each write)
function counted() {
  const e = { writes: 0, _t: '', classes: new Set(), style: {}, value: '', disabled: false, placeholder: '', innerHTML: '',
              children: [], scrollTop: 0, scrollHeight: 100, dataset: {} };
  Object.defineProperty(e, 'textContent', { get() { return e._t; }, set(v) { e._t = v; e.writes++; } });
  e.classList = { toggle: (c, on) => { if (on) e.classes.add(c); else e.classes.delete(c); } };
  e.setAttribute = () => {};
  e.appendChild = (c) => { e.children.push(c); return c; };
  return e;
}
const els = { 'voice-meter-fill': counted(), 'voice-meter': counted(), 'voice-meter-note': counted(), 'voice-loopback': counted(),
              'chat-messages': counted(), 'chat-input': counted(), 'send-btn': counted() };
const hist = [];
const sandbox = {
  document: { getElementById: (id) => els[id], createElement: () => counted() },
  voiceMeterPct: () => 50,
  VoiceChat: { getPrefs: () => ({ vadThreshold: -40 }) },
  escapeHtml: (t) => String(t),
  resetHistoryState: () => hist.push('reset'),
  channelUnavailable: false,
  console,
};
vm.createContext(sandbox);
vm.runInContext(fn('onVoiceMeterLevel') + '\n' + fn('showChannelUnavailable') + '\n' + fn('appendSystemMessage') +
                '\nthis.api = { onVoiceMeterLevel, showChannelUnavailable };', sandbox);
const api = sandbox.api;

const note = els['voice-meter-note'];
api.onVoiceMeterLevel({ db: -50, inCall: true });
const w1 = note.writes;
for (let i = 0; i < 20; i++) api.onVoiceMeterLevel({ db: -50 + i, inCall: true });
check('the meter note is written once while its text stays the same', w1 === 1 && note.writes === 1, note.writes);
api.onVoiceMeterLevel({ db: -50, inCall: false });
check('the meter note is written again when its text changes', note.writes === 2 && note.textContent === '', note.writes);
api.onVoiceMeterLevel({ error: 'No microphone', db: -100 });
check('an error text replaces it', note.textContent === 'No microphone' && note.writes === 3);

els['chat-messages'].innerHTML = '<div>old rows</div>';
api.showChannelUnavailable();
check('the lost channel clears the list and shows one plain system line',
  els['chat-messages'].innerHTML === '' && els['chat-messages'].children.length === 1 &&
  els['chat-messages'].children[0].className === 'message system' &&
  els['chat-messages'].children[0].innerHTML.includes('no longer available'));
check('sending is disabled and the history state reset', els['chat-input'].disabled && els['send-btn'].disabled &&
  sandbox.channelUnavailable === true && hist.length === 1);
for (const r of results) console.log('RESULT ' + JSON.stringify(r));

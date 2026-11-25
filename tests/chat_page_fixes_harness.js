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
  currentView: 'channel', currentChannel: 'general', HistoryView: { channelId: 1 },
  channelsList: [{ id: 1, name: 'general' }, { id: 2, name: 'music' }],
  console,
};
vm.createContext(sandbox);
vm.runInContext(fn('onVoiceMeterLevel') + '\n' + fn('showChannelUnavailable') + '\n' + fn('appendSystemMessage') + '\n' + fn('refusalRoomName') + '\n' + fn('removeDeletedMessage') + '\n' + (html.includes('function removeDeletedMessages(') ? fn('removeDeletedMessages') : '') +
                '\nthis.api = { onVoiceMeterLevel, showChannelUnavailable, refusalRoomName, removeDeletedMessage, pruned: (typeof removeDeletedMessages === "function" ? removeDeletedMessages : null) };', sandbox);
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
// a refusal frame names the room it is about when that is not the open room
check('a refusal without channel_id is not attributed to another room', api.refusalRoomName({ type: 'error', message: 'x' }) === '' && api.refusalRoomName({ channel_id: null }) === '');
check('a refusal about the open room is not attributed to another room', api.refusalRoomName({ channel_id: 1 }) === '' && api.refusalRoomName({ channel_id: '1' }) === '');
check('a refusal about another known room names it', api.refusalRoomName({ channel_id: 2 }) === '#music', api.refusalRoomName({ channel_id: 2 }));
check('a refusal about a room not in the list says another room', api.refusalRoomName({ channel_id: 99 }) === 'another room');
check('a channel_id that is not an integer is ignored', api.refusalRoomName({ channel_id: 'music' }) === '' && api.refusalRoomName({ channel_id: 1.5 }) === '');
sandbox.currentView = 'dm';
check('a refusal about a channel while a direct message is shown names the channel', api.refusalRoomName({ channel_id: 1 }) === '#general');
sandbox.currentView = 'channel'; sandbox.channelsList = []; sandbox.HistoryView.channelId = null;
check('the open room is unknown: the frame is shown as before', api.refusalRoomName({ channel_id: 2 }) === '');
sandbox.channelsList = []; sandbox.HistoryView.channelId = 1;
check('the open room is known only by the shown rows: its own id is not another room', api.refusalRoomName({ channel_id: 1 }) === '' && api.refusalRoomName({ channel_id: 2 }) === 'another room');
// a prune frame of 200 ids: the rows go, the history bar and the pinned panel are updated once
{
  const rows = new Map(), previews = [];
  for (let i = 1; i <= 300; i++) rows.set(i, { removed: false, remove() { this.removed = true; } });
  const preview = { cls: new Set(), attrs: { 'data-reply-id': '5' }, classList: { add(c) { preview.cls.add(c); } }, removeAttribute(k) { delete preview.attrs[k]; } };
  let bars = 0, pinnedDraws = 0;
  sandbox.CSS = { escape: String };
  sandbox.document.querySelector = (q) => { const m = /data-message-id="(\d+)"/.exec(q); return m ? rows.get(Number(m[1])) || null : null; };
  sandbox.document.querySelectorAll = (q) => /data-reply-id="5"/.test(q) ? [preview] : [];
  sandbox.updateHistoryBar = () => { bars++; };
  sandbox.renderPinnedMessages = () => { pinnedDraws++; };
  sandbox.HistoryView = { buffer: [{ id: 1 }, { id: 250 }, { id: 7 }] };
  sandbox.pinnedMessages = [{ id: 3 }, { id: 260 }];
  const ids = []; for (let i = 1; i <= 200; i++) ids.push(i);
  if (api.pruned) api.pruned(ids); else ids.forEach(api.removeDeletedMessage);
  let gone = 0; rows.forEach((r, i) => { if (r.removed === (i <= 200)) gone++; });
  check('a prune frame of 200 ids removes exactly those rows', gone === 300);
  check('the history bar is updated once for the whole frame', bars === 1, bars);
  check('the pinned panel is drawn once for the whole frame', pinnedDraws === 1 && sandbox.pinnedMessages.length === 1 && sandbox.pinnedMessages[0].id === 260, pinnedDraws);
  check('the buffer drops the pruned ids and keeps the others', sandbox.HistoryView.buffer.length === 1 && sandbox.HistoryView.buffer[0].id === 250);
  check('a reply preview that points to a pruned message is marked deleted', preview.cls.has('reply-deleted') && !('data-reply-id' in preview.attrs));
  bars = 0; pinnedDraws = 0; sandbox.pinnedMessages = [{ id: 260 }];
  api.removeDeletedMessage(250);
  check('a single message_deleted still updates the bar once and does not draw the pinned panel when nothing pinned went', bars === 1 && pinnedDraws === 0);
  bars = 0; sandbox.pinnedMessages = [{ id: 260 }];
  if (api.pruned) api.pruned([]);
  check('an empty prune frame changes nothing visible', pinnedDraws === 0);
}
for (const r of results) console.log('RESULT ' + JSON.stringify(r));

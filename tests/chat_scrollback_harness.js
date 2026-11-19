// Runs the scrollback block of static/chat.html (older pages, jump to a message,
// Jump to present, live buffer) under Node against a small fake page. Used by
// tests/test_chat_scrollback_client.py.
//
// usage: node chat_scrollback_harness.js <path to chat.html>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(process.argv[2], 'utf8');
const start = html.indexOf('const HISTORY_TOP_PX');
const endMarker = 'window.chatJumpToMessage = jumpToChannelMessage;';
const end = html.indexOf(endMarker);
if (start < 0 || end < 0) { console.log('RESULT ' + JSON.stringify({ name: 'scrollback block found', ok: false, detail: 'markers missing' })); process.exit(0); }
const delStart = html.indexOf('function removeDeletedMessage(');
const delEnd = html.indexOf('// Scrollback: older pages on scroll');
const DELETE_FN = delStart >= 0 && delEnd > delStart ? html.slice(delStart, delEnd) : '';
const BLOCK = DELETE_FN + '\n' + html.slice(start, end + endMarker.length);

const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

class Row {
  constructor(id, container) {
    this.dataset = { messageId: String(id) };
    this.container = container;
    this.classes = new Set();
    this.classList = { add: c => this.classes.add(c), remove: c => this.classes.delete(c), toggle: () => {} };
    this.scrolled = false;
  }
  remove() { this.container.children = this.container.children.filter(r => r !== this); }
  getBoundingClientRect() { return { top: this.container.children.indexOf(this) * 10 - this.container.scrollTop }; }
  scrollIntoView() { this.scrolled = true; }
  closest() { return null; }
}

function makePage() {
  const container = { children: [], scrollTop: 0, scrollHeight: 4000, clientHeight: 500 };
  container.insertBefore = (row, ref) => {
    const i = ref ? container.children.indexOf(ref) : -1;
    if (i < 0) container.children.push(row); else container.children.splice(i, 0, row);
  };
  container.querySelectorAll = () => container.children.slice();
  container.querySelector = () => null;
  container.innerHTML = '';
  const els = {
    'chat-messages': container,
    'history-bar': { classList: { toggle() {} } },
    'history-status': { textContent: '' },
    'history-jump-btn': { style: {}, textContent: '' },
  };
  const polls = [], sent = [], toasts = [], observed = new Set(), unobserved = [], appended = [], switched = [], marked = [];
  const ws = { readyState: 1, send: (s) => sent.push(JSON.parse(s)) };
  const ctx = {
    document: {
      getElementById: (id) => els[id],
      querySelectorAll: () => [],
      querySelector: (sel) => {
        const m = sel.match(/data-message-id="([^"]*)"/);
        return m ? container.children.find(r => r.dataset.messageId === m[1]) || null : null;
      },
    },
    CSS: { escape: (s) => String(s) },
    WebSocket: { OPEN: 1 },
    ws, currentView: 'channel', currentChannel: 'general', currentUser: { id: 5 },
    channelsList: [{ id: 1, name: 'general' }, { id: 2, name: 'other' }],
    knownChatNames: new Set(),
    requestAnimationFrame: (fn) => fn(),
    setTimeout: (fn) => 0, clearTimeout: () => {},
    Date,
    console,
    Portal: { toast: (m) => toasts.push(m) },
    showToast: (m) => toasts.push(m),
    _readObserver: { unobserve: (el) => unobserved.push(el) },
    openThread: () => {},
    appendPollMessage(data) {
      const row = new Row(data.message_id, container);
      container.insertBefore(row, null);
      polls.push(data.message_id);
    },
    switchToChannel: (n) => switched.push(n),
    pinnedMessages: [],
    renderPinnedMessages: () => {},
    markAsRead: (id) => marked.push(id),
    _lastReadMessageId: 0,
    renderHistory(messages, opts) {
      container.children = [];
      for (const m of messages) ctx.appendMessage(m, false, opts && opts.fetched ? { fetched: true } : null);
      container.scrollTop = container.scrollHeight;
    },
    appendMessage(data, scroll = true, opts = null) {
      const row = new Row(data.id, container);
      container.insertBefore(row, opts && opts.before ? opts.before : null);
      appended.push({ id: data.id, fetched: !!(opts && opts.fetched) });
      if (!(opts && opts.fetched)) observed.add(data.id);
      if (scroll) container.scrollTop = container.scrollHeight;
      return row;
    },
    window: {},
  };
  vm.createContext(ctx);
  vm.runInContext(BLOCK, ctx);
  return { ctx, polls, container, sent, toasts, observed, unobserved, appended, switched, marked, ws };
}
const run = (p, code) => vm.runInContext(code, p.ctx);
const ids = (p) => p.container.children.map(r => Number(r.dataset.messageId));
const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);
const msgs = (a, b) => range(a, b).map(id => ({ id }));

function join(p, from, to, hasMore, channelId = 1) {
  p.ctx.renderHistory(msgs(from, to));
  p.ctx.onJoinHistory({ channel_id: channelId, has_more: hasMore });
  p.container.scrollTop = 0;
}

// ---- older pages --------------------------------------------------------------
{
  const p = makePage();
  join(p, 101, 150, true);
  p.sent.length = 0;
  p.container.scrollTop = 50;
  run(p, 'maybeLoadOlder()');
  check('scrolling near the top asks for the page before the first row',
        p.sent.length === 1 && p.sent[0].type === 'history_page' && p.sent[0].before_id === 101 && p.sent[0].req > 0, JSON.stringify(p.sent));
  run(p, 'maybeLoadOlder()');
  check('no second request while one is in flight', p.sent.length === 1);
  const req = p.sent[0].req;
  // a stale reply (wrong request number) and one for another channel are dropped
  run(p, `onHistoryOlder({req: ${req + 5}, channel_id: 1, messages: [{id: 99}], has_more: true})`);
  run(p, `onHistoryOlder({req: ${req}, channel_id: 2, messages: [{id: 99}], has_more: true})`);
  check('replies for another request or channel are ignored', ids(p).length === 50 && run(p, 'HistoryView.loading') === true);
  p.container.scrollTop = 300;
  const before = p.container.children[0].getBoundingClientRect().top;
  // page 51..100, plus 101 (already shown) which must not appear twice
  run(p, `onHistoryOlder({req: ${req}, channel_id: 1, messages: ${JSON.stringify(msgs(51, 101))}, has_more: true})`);
  check('older rows are placed above, in order, without duplicates', JSON.stringify(ids(p)) === JSON.stringify(range(51, 150)), ids(p).slice(0, 3));
  check('the rows already shown keep their place on screen (scroll position corrected)',
        p.container.scrollTop === 300 + 500 && true, p.container.scrollTop);
  check('fetched rows are not handed to read tracking',
        p.appended.filter(a => a.id >= 51 && a.id <= 100).every(a => a.fetched) && ![...p.observed].some(i => i >= 51 && i <= 100));
  check('has_more stays true until the server says otherwise', run(p, 'HistoryView.hasMore') === true && run(p, 'HistoryView.loading') === false);
  p.sent.length = 0;
  p.container.scrollTop = 10;
  run(p, 'maybeLoadOlder()');
  const req2 = p.sent[0].req;
  run(p, `onHistoryOlder({req: ${req2}, channel_id: 1, messages: ${JSON.stringify(msgs(1, 50))}, has_more: false})`);
  p.container.scrollTop = 10;
  p.sent.length = 0;
  run(p, 'maybeLoadOlder()');
  check('walking to the start loads every row once and then stops asking',
        JSON.stringify(ids(p)) === JSON.stringify(range(1, 150)) && p.sent.length === 0);
}

// ---- the DOM cap and the detached state ----------------------------------------
{
  const p = makePage();
  join(p, 301, 700, true);
  p.container.scrollTop = 10;
  p.sent.length = 0;
  run(p, 'maybeLoadOlder()');
  const req = p.sent[0].req;
  run(p, `onHistoryOlder({req: ${req}, channel_id: 1, messages: ${JSON.stringify(msgs(200, 300))}, has_more: true})`);
  check('far rows are dropped from the end opposite the reader (page capped at 400 rows)',
        ids(p).length === 400 && ids(p)[0] === 200 && ids(p)[399] === 599, `${ids(p).length} ${ids(p)[0]}..${ids(p)[ids(p).length - 1]}`);
  check('dropped rows are released from the read observer', p.unobserved.length === 101);
  check('dropping the newest rows leaves the present: detached', run(p, 'HistoryView.detached') === true);
  run(p, 'appendLiveMessage({id: 701, user_id: 9})');
  check('a live message while detached goes to the buffer, not to the page', ids(p).length === 400 && run(p, 'HistoryView.buffer.length') === 1);
}

// ---- around a message, live buffer, jump to present -----------------------------
{
  const p = makePage();
  join(p, 201, 250, true);
  p.sent.length = 0;
  run(p, 'scrollToMessage(40)');
  check('a message that is not on the page is requested as a window around it',
        p.sent.length === 1 && p.sent[0].around_id === 40 && p.sent[0].before_id === undefined, JSON.stringify(p.sent));
  run(p, 'appendLiveMessage({id: 251, user_id: 9})');
  check('a live message while the window is on its way is held, not appended', ids(p).length === 50 && run(p, 'HistoryView.buffer.length') === 1);
  const req = p.sent[0].req;
  p.appended.length = 0;
  run(p, `onHistoryAround({req: ${req}, channel_id: 1, found: true, has_more: true, has_newer: true, messages: ${JSON.stringify(msgs(15, 64))}})`);
  const row = p.container.children.find(r => r.dataset.messageId === '40');
  check('the window replaces the rows and shows the target', JSON.stringify(ids(p)) === JSON.stringify(range(15, 64)) && row.scrolled && row.classes.has('highlight'));
  check('rows of a window are never marked as read', p.appended.every(a => a.fetched) && p.observed.has(201));
  check('a window that stops short of the present is detached', run(p, 'HistoryView.detached') === true && run(p, 'HistoryView.hasMore') === true);
  run(p, 'appendLiveMessage({id: 252, user_id: 9})');
  run(p, 'appendLiveMessage({id: 252, user_id: 9})');
  check('live messages are buffered once each while viewing a window', ids(p).length === 50 && run(p, 'HistoryView.buffer.length') === 2);
  p.sent.length = 0;
  run(p, 'jumpToPresent()');
  check('Jump to present asks for the newest page (no cursor)',
        p.sent.length === 1 && p.sent[0].type === 'history_page' && p.sent[0].before_id === undefined && p.sent[0].around_id === undefined);
  run(p, 'appendLiveMessage({id: 253, user_id: 9})');
  const req2 = p.sent[0].req;
  p.appended.length = 0;
  run(p, `onHistoryAround({req: ${req2}, channel_id: 1, found: true, has_more: true, has_newer: false, messages: ${JSON.stringify(msgs(203, 252))}})`);
  check('back at the present: newest page shown, buffered messages newer than it appended once, none twice',
        JSON.stringify(ids(p)) === JSON.stringify(range(203, 253)) && run(p, 'HistoryView.buffer.length') === 0 && run(p, 'HistoryView.detached') === false,
        ids(p).slice(-3));
  run(p, 'appendLiveMessage({id: 254, user_id: 9})');
  check('after that live messages are appended again', ids(p)[ids(p).length - 1] === 254);
}

// ---- more live messages while detached than one page holds ---------------------------
{
  const p = makePage();
  join(p, 201, 250, true);
  p.sent.length = 0;
  run(p, 'scrollToMessage(40)');
  const req = p.sent[0].req;
  run(p, `onHistoryAround({req: ${req}, channel_id: 1, found: true, has_more: true, has_newer: true, messages: ${JSON.stringify(msgs(15, 64))}})`);
  for (let id = 251; id <= 320; id++) {
    if (id === 260) run(p, 'appendLivePoll({message_id: 260, poll: {id: 9}})');
    else run(p, `appendLiveMessage({id: ${id}, user_id: 9})`);
  }
  check('seventy messages and a poll wait in the buffer while a window is shown', ids(p).length === 50 && run(p, 'HistoryView.buffer.length') === 70);
  p.sent.length = 0;
  run(p, 'jumpToPresent()');
  const req2 = p.sent[0].req;
  run(p, 'appendLiveMessage({id: 321, user_id: 9})');
  run(p, 'appendLivePoll({message_id: 322, poll: {id: 10}})');
  p.appended.length = 0;
  p.polls.length = 0;
  run(p, `onHistoryAround({req: ${req2}, channel_id: 1, found: true, has_more: true, has_newer: false, messages: ${JSON.stringify(msgs(271, 320))}})`);
  const got = ids(p);
  check('Jump to present with more than a page buffered: rows stay in ascending order',
        got.every((v, i) => i === 0 || v > got[i - 1]), got.join(',').slice(0, 120));
  check('buffered messages older than the newest page are not appended below it',
        JSON.stringify(got) === JSON.stringify(range(271, 322)) && !p.polls.includes(260), got.slice(0, 3) + '...' + got.slice(-3));
  check('only buffered messages newer than the page are added (no fetched flag, read tracking sees them)',
        p.appended.filter(a => !a.fetched).map(a => a.id).join() === '321' && p.polls.join() === '322', JSON.stringify(p.appended.filter(a => !a.fetched)));
}

// ---- polls are announced by their own event and wait like messages ----------------------
{
  const p = makePage();
  join(p, 201, 250, true);
  run(p, 'appendLivePoll({message_id: 251, poll: {id: 1}})');
  check('a poll at the present is added to the page', ids(p)[ids(p).length - 1] === 251 && p.polls.length === 1);
  run(p, 'appendLivePoll({message_id: 251, poll: {id: 1}})');
  check('the same poll is not added twice', ids(p).filter(i => i === 251).length === 1);
  p.sent.length = 0;
  run(p, 'scrollToMessage(40)');
  run(p, 'appendLivePoll({message_id: 252, poll: {id: 2}})');
  check('a poll announced while a window is on its way is held, not appended', !ids(p).includes(252) && run(p, 'HistoryView.buffer.length') === 1);
  const req = p.sent[0].req;
  run(p, `onHistoryAround({req: ${req}, channel_id: 1, found: true, has_more: true, has_newer: true, messages: ${JSON.stringify(msgs(15, 64))}})`);
  run(p, 'appendLivePoll({message_id: 253, poll: {id: 3}})');
  check('a poll announced while a window is shown waits in the buffer', !ids(p).includes(253) && run(p, 'HistoryView.buffer.length') === 2);
  p.sent.length = 0;
  run(p, 'jumpToPresent()');
  const req2 = p.sent[0].req;
  p.polls.length = 0;
  run(p, `onHistoryAround({req: ${req2}, channel_id: 1, found: true, has_more: true, has_newer: false, messages: ${JSON.stringify(msgs(204, 252))}})`);
  check('Jump to present shows the buffered polls the newest page lacks, once',
        ids(p).filter(i => i === 253).length === 1 && ids(p).filter(i => i === 252).length === 1 && p.polls.join() === '253', p.polls.join());
}

// ---- not found, errors, rate limit ------------------------------------------------
{
  const p = makePage();
  join(p, 201, 250, true);
  p.sent.length = 0;
  run(p, 'scrollToMessage(7)');
  run(p, 'appendLiveMessage({id: 251, user_id: 9})');
  const req = p.sent[0].req;
  run(p, `onHistoryAround({req: ${req}, channel_id: 1, found: false, has_more: false, has_newer: false, messages: []})`);
  check('a message that is gone: a notice, the page untouched, held live messages shown',
        p.toasts.length === 1 && ids(p).length === 51 && ids(p)[50] === 251 && run(p, 'HistoryView.buffer.length') === 0, p.toasts.join('|'));
  p.container.scrollTop = 10;
  p.sent.length = 0;
  run(p, 'maybeLoadOlder()');
  const r2 = p.sent[0].req;
  run(p, `onHistoryError({req: ${r2}, error_code: 'rate_limited', retry_after: 20})`);
  p.sent.length = 0;
  run(p, 'maybeLoadOlder()');
  check('after a rate limit answer no request is made until the wait is over', p.sent.length === 0 && run(p, 'HistoryView.loading') === false);
}

// ---- reset on switching channels, links from other channels -------------------------
{
  const p = makePage();
  join(p, 101, 150, true);
  p.sent.length = 0;
  p.container.scrollTop = 10;
  run(p, 'maybeLoadOlder()');
  const req = p.sent[0].req;
  run(p, 'resetHistoryState()');
  run(p, `onHistoryOlder({req: ${req}, channel_id: 1, messages: ${JSON.stringify(msgs(51, 100))}, has_more: true})`);
  check('a reply that arrives after a channel switch is dropped', ids(p).length === 50);
  join(p, 1, 20, true, 1);
  p.sent.length = 0;
  run(p, 'jumpToChannelMessage(2, 77)');
  check('a link to another channel switches to it and remembers the message',
        p.switched.join() === 'other' && JSON.stringify(run(p, 'HistoryView.pendingJump')) === JSON.stringify({ channelId: 2, messageId: 77 }));
  p.ctx.renderHistory(msgs(300, 349));
  run(p, 'onJoinHistory({channel_id: 2, has_more: true})');
  check('when that channel\'s history arrives the message is requested in context',
        p.sent.length === 1 && p.sent[0].around_id === 77, JSON.stringify(p.sent));
  p.sent.length = 0;
  run(p, 'jumpToChannelMessage(3, 5)');
  check('a link to a channel the member does not have is refused with a notice', p.sent.length === 0 && p.toasts.length > 0);
}

// ---- updates of a message that waits in the live buffer -----------------------------------
{
  const p = makePage();
  join(p, 201, 250, true);
  p.sent.length = 0;
  run(p, 'scrollToMessage(40)');
  const req = p.sent[0].req;
  run(p, `onHistoryAround({req: ${req}, channel_id: 1, found: true, has_more: true, has_newer: true, messages: ${JSON.stringify(msgs(15, 64))}})`);
  run(p, 'appendLiveMessage({id: 251, user_id: 9, message: "old text", reactions: []})');
  run(p, 'appendLiveMessage({id: 252, user_id: 9, message: "will be deleted"})');
  run(p, 'appendLiveMessage({id: 253, user_id: 9, message: "reacted", reactions: [{emoji: "x", count: 1, user_ids: [4]}]})');
  run(p, 'appendLivePoll({message_id: 254, poll: {id: 7, votes: {}}, username: "u"})');
  run(p, 'bufferApplyEdit({message_id: 251, message: "new text", edited_at: "2026-01-01T00:00:00"})');
  run(p, 'bufferApplyEdit({message_id: 999, message: "not buffered"})');
  run(p, 'bufferApplyReaction({message_id: 251, emoji: "a", user_id: 5, added: true, count: 1})');
  run(p, 'bufferApplyReaction({message_id: 253, emoji: "x", user_id: 6, added: true, count: 2})');
  run(p, 'bufferApplyReaction({message_id: 253, emoji: "x", user_id: 4, added: false, count: 1})');
  run(p, 'bufferApplyReaction({message_id: 253, emoji: "y", user_id: 4, added: true, count: 1})');
  run(p, 'bufferApplyReaction({message_id: 253, emoji: "y", user_id: 4, added: false, count: 0})');
  run(p, 'bufferApplyPoll({id: 7, votes: {"0": 3}})');
  const buf = JSON.parse(run(p, 'JSON.stringify(HistoryView.buffer)'));
  const by = (id) => buf.find(m => m.id === id);
  check('an edit changes the buffered entry (text and edited time)', by(251).message === 'new text' && by(251).edited_at === '2026-01-01T00:00:00', JSON.stringify(by(251)));
  check('an edit of a message that is not buffered changes nothing', buf.length === 4 && !buf.some(m => m.message === 'not buffered'));
  check('a reaction is added to a buffered entry, with the reactor', JSON.stringify(by(251).reactions) === JSON.stringify([{ emoji: 'a', count: 1, user_ids: [5] }]), JSON.stringify(by(251).reactions));
  check('a reaction change updates count and reactors, and a count of 0 removes the reaction',
        JSON.stringify(by(253).reactions) === JSON.stringify([{ emoji: 'x', count: 1, user_ids: [6] }]), JSON.stringify(by(253).reactions));
  check('a poll update replaces the poll of a buffered poll entry', by(254).poll.votes['0'] === 3, JSON.stringify(by(254).poll));
  run(p, 'removeDeletedMessage(252)');
  check('a deleted message leaves the buffer', run(p, 'HistoryView.buffer.some(m => m.id === 252)') === false && run(p, 'HistoryView.buffer.length') === 3);
}

// ---- Jump to present marks the newest page read; a send while detached jumps -------------------
{
  const p = makePage();
  join(p, 201, 250, true);
  p.sent.length = 0;
  run(p, 'jumpToPresentAfterSend()');
  check('jumpToPresentAfterSend does nothing at the present', p.sent.length === 0, JSON.stringify(p.sent));
  run(p, 'scrollToMessage(40)');
  const req = p.sent[0].req;
  run(p, `onHistoryAround({req: ${req}, channel_id: 1, found: true, has_more: true, has_newer: true, messages: ${JSON.stringify(msgs(15, 64))}})`);
  check('a window is not marked read', p.marked.length === 0);
  p.sent.length = 0;
  run(p, 'jumpToPresentAfterSend()');
  check('sending while detached asks for the newest page (no cursor)',
        p.sent.length === 1 && p.sent[0].type === 'history_page' && p.sent[0].before_id === undefined && p.sent[0].around_id === undefined, JSON.stringify(p.sent));
  const req2 = p.sent[0].req;
  run(p, `onHistoryAround({req: ${req2}, channel_id: 1, found: true, has_more: true, has_newer: false, messages: ${JSON.stringify(msgs(203, 252))}})`);
  check('Jump to present marks the last message of the newest page read, once', p.marked.join() === '252' && run(p, '_lastReadMessageId') === 252, p.marked.join());
  p.sent.length = 0;
  run(p, 'jumpToPresentAfterSend()');
  check('after the jump the view is at the present again and a send asks for nothing', p.sent.length === 0 && run(p, 'HistoryView.detached') === false);
  // an around window is never marked, even when it reaches the present
  const q = makePage();
  join(q, 201, 250, true);
  q.sent.length = 0;
  run(q, 'scrollToMessage(40)');
  run(q, `onHistoryAround({req: ${q.sent[0].req}, channel_id: 1, found: true, has_more: true, has_newer: false, messages: ${JSON.stringify(msgs(230, 250))}})`);
  check('a window that reaches the present is still not marked read', q.marked.length === 0);
}

for (const r of results) console.log('RESULT ' + JSON.stringify(r));

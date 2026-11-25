// Runs loadChannels of static/chat.html under Node against fakes: the Mentions-only badge is
// seeded from the channel list answer after a reload.
// usage: node unread_mentions_harness.js <chat.html>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(process.argv[2], 'utf8');
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }
function fn(name, asyncFn) {
  const head = (asyncFn ? 'async function ' : 'function ') + name + '(';
  const a = html.indexOf(head);
  if (a < 0) throw new Error('function not found: ' + name);
  const b = html.indexOf('\n        function ', a + 10);
  const c = html.indexOf('\n        async function ', a + 10);
  const d = html.indexOf('\n        // ', a + 10);
  const e = html.indexOf('\n        let ', a + 10);
  const end = [b, c, d, e].filter(x => x > 0).reduce((m, x) => Math.min(m, x), Infinity);
  return html.slice(a, end);
}
const NOW = 1_800_000_000_000;
const CN = require(process.argv[3]);

(async () => {
  const rendered = [];
  const answer = { channels: [] };
  const sb = {
    fetch: async () => ({ json: async () => answer }),
    console, currentChannel: 'general', currentView: 'channel', _starsMigrated: true,
    unreadCounts: new Map(), unreadMentions: new Map(),
    renderChannels: (list) => rendered.push(list), ChatNotify: {}, localStorage: {},
  };
  vm.createContext(sb);
  vm.runInContext(fn('loadChannels', true) + '\nthis.loadChannels = loadChannels;', sb);

  answer.channels = [
    { id: 1, name: 'general', unread_count: 0, unread_mentions: 4 },
    { id: 2, name: 'ment', unread_count: 6, unread_mentions: 2, notify_level: 'mentions' },
    { id: 3, name: 'quiet', unread_count: 0, unread_mentions: 0 },
    { id: 4, name: 'old', unread_count: 3 },                       // an older server: no field
  ];
  sb.unreadMentions.set('quiet', 9);                                // a stale live count
  sb.unreadMentions.set('gone', 3);
  await sb.loadChannels();
  check('a reload seeds the mention count of a channel from the answer', sb.unreadMentions.get('ment') === 2, [...sb.unreadMentions]);
  check('the room on screen gets no badge', !sb.unreadMentions.has('general'));
  check('a channel with none, or an answer without the field, has none', !sb.unreadMentions.has('quiet') && !sb.unreadMentions.has('old'));
  check('a count the server no longer has is dropped', !sb.unreadMentions.has('gone'));
  check('the ordinary unread counts are rebuilt as before', sb.unreadCounts.get('ment') === 6 && sb.unreadCounts.get('old') === 3 && !sb.unreadCounts.has('general'));
  check('the list is drawn after the counts', rendered.length === 1 && rendered[0] === answer.channels);
  sb.currentChannel = 'ment';
  await sb.loadChannels();
  check('opening the channel clears its badge on the next load', !sb.unreadMentions.has('ment'));
  // the badge itself: renderChannelItem shows the mention count in Mentions mode only
  const ch = { id: 2, name: 'ment', notify_level: 'mentions', muted_until: 0 };
  check('badge mode for the channel is mentions', CN.badgeMode(ch, NOW) === 'mentions');

  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness ran', ok: false, detail: e.stack })); });

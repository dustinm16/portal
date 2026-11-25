// Runs static/js/chat-notify.js and the notification handlers of static/chat.html under Node
// against fakes. Used by tests/test_chat_notify_client.py.
// usage: node chat_notify_harness.js <chat.html> <chat-notify.js>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(process.argv[2], 'utf8');
const CN = require(process.argv[3]);
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }
function fn(name) {
  const a = html.indexOf('function ' + name + '(');
  if (a < 0) throw new Error('function not found: ' + name);
  const b = html.indexOf('\n        function ', a + 10);
  const c = html.indexOf('\n        // ', a + 10);
  const end = [b, c].filter(x => x > 0).reduce((m, x) => Math.min(m, x), Infinity);
  return html.slice(a, end);
}
function store(initial) {
  const m = new Map(Object.entries(initial || {}));
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), _m: m };
}
const NOW = 1_800_000_000_000;

(async () => {
  // level and mute
  const dflt = { id: 1, name: 'a', notify_level: null, muted_until: 0 };
  const muted = { id: 2, name: 'b', notify_level: 'all', muted_until: NOW / 1000 + 8 * 3600 };
  const expired = { id: 3, name: 'c', notify_level: 'all', muted_until: NOW / 1000 - 5 };
  check('default: badge for everything, no ordinary alert', CN.badgeMode(dflt, NOW) === 'all' && !CN.alertWanted(dflt, false, NOW));
  check('all: badge and alert', CN.badgeMode({ notify_level: 'all', muted_until: 0 }, NOW) === 'all'
        && CN.alertWanted({ notify_level: 'all', muted_until: 0 }, false, NOW));
  check('mute: no badge, no ordinary alert, a mention still alerts',
        CN.badgeMode(muted, NOW) === 'none' && !CN.alertWanted(muted, false, NOW) && CN.alertWanted(muted, true, NOW));
  check('an ended mute counts again', CN.badgeMode(expired, NOW) === 'all' && CN.alertWanted(expired, false, NOW));
  check('mentions level: badge only for mentions, mention alerts', CN.badgeMode({ notify_level: 'mentions' }, NOW) === 'mentions'
        && !CN.alertWanted({ notify_level: 'mentions' }, false, NOW) && CN.alertWanted({ notify_level: 'mentions' }, true, NOW));
  check('none: nothing, not even a mention', CN.badgeMode({ notify_level: 'none' }, NOW) === 'none'
        && !CN.alertWanted({ notify_level: 'none' }, true, NOW));

  // quiet hours
  const q = { quiet: true, start: '22:00', end: '07:00' };
  const at = (h, m) => new Date(2026, 10, 20, h, m);
  check('quiet hours wrap past midnight', CN.inQuietHours(q, at(23, 0)) && CN.inQuietHours(q, at(3, 30)) && CN.inQuietHours(q, at(22, 0))
        && !CN.inQuietHours(q, at(7, 0)) && !CN.inQuietHours(q, at(12, 0)) && !CN.inQuietHours(q, at(21, 59)));
  check('quiet hours same day', CN.inQuietHours({ quiet: true, start: '13:00', end: '14:00' }, at(13, 30))
        && !CN.inQuietHours({ quiet: true, start: '13:00', end: '14:00' }, at(14, 0)));
  check('quiet off or empty window', !CN.inQuietHours({ quiet: false, start: '00:00', end: '23:59' }, at(5, 0))
        && !CN.inQuietHours({ quiet: true, start: '08:00', end: '08:00' }, at(8, 0)));
  const st = store();
  check('sound is on by default and bad stored values fall back', CN.soundAllowed(st, at(12, 0)));
  st.setItem('portal_chat_sound', '{"enabled":"yes","start":"99:99","quiet":true}');
  check('a garbled setting keeps the defaults', CN.readSoundSettings(st).start === '22:00' && CN.readSoundSettings(st).enabled === true);
  CN.writeSoundSettings(st, { enabled: true, quiet: true, start: '22:00', end: '07:00' });
  check('quiet hours silence the sound', !CN.soundAllowed(st, at(23, 0)) && CN.soundAllowed(st, at(12, 0)));
  CN.writeSoundSettings(st, { enabled: false, quiet: false });
  check('sound off silences it', !CN.soundAllowed(st, at(12, 0)));

  // one tab plays: navigator.locks
  const held = new Set();
  const fakeNav = { locks: { request: (name, opts, cb) => {
    if (opts.ifAvailable && held.has(name)) return Promise.resolve(cb(null));
    held.add(name);
    return Promise.resolve(cb({ name })).then(() => held.delete(name));
  } } };
  const timers = [];
  const env = { navigator: fakeNav, storage: store(), setTimeout: (f) => timers.push(f) };
  const r = await Promise.all([CN.claimSound(env), CN.claimSound(env), CN.claimSound(env)]);
  check('locks: exactly one of three tabs plays', r.filter(Boolean).length === 1, JSON.stringify(r));
  timers.forEach(f => f());
  await new Promise(res => setImmediate(res));
  check('locks: released after the hold, the next sound may play', (await CN.claimSound({ ...env, setTimeout: () => {} })) === true);

  // fallback: a timestamp in storage
  const shared = store();
  let clock = NOW;
  const e2 = { navigator: {}, storage: shared, now: () => clock };
  const a1 = await CN.claimSound(e2), a2 = await CN.claimSound(e2);
  clock += 1600;
  const a3 = await CN.claimSound(e2);
  check('storage lock: the second within 1.5 s is refused, later ones play', a1 === true && a2 === false && a3 === true, [a1, a2, a3]);

  // a tab that cannot be heard does not take the sound lock
  {
    let asked = 0;
    const lockNav = { locks: { request: (name, opts, cb) => { asked++; return Promise.resolve(cb({ name })); } } };
    const base = { navigator: lockNav, storage: store(), setTimeout: () => {} };
    const hiddenSilent = await CN.claimSound({ ...base, document: { hidden: true }, audioState: 'suspended' });
    check('locks: a hidden tab with a suspended audio context does not take the lock', hiddenSilent === false && asked === 0, [hiddenSilent, asked]);
    const hiddenNone = await CN.claimSound({ ...base, document: { hidden: true } });
    check('locks: a hidden tab with no audio context at all does not take the lock', hiddenNone === false && asked === 0, [hiddenNone, asked]);
    const hiddenRunning = await CN.claimSound({ ...base, document: { hidden: true }, audioState: 'running' });
    check('locks: a hidden tab whose audio context is running may take it', hiddenRunning === true && asked === 1, [hiddenRunning, asked]);
    const visible = await CN.claimSound({ ...base, document: { hidden: false }, audioState: 'suspended' });
    check('locks: a visible tab may take it', visible === true && asked === 2, [visible, asked]);
    const st2 = store();
    const sEnv = { navigator: {}, storage: st2, now: () => NOW, document: { hidden: true }, audioState: 'suspended' };
    const sHidden = await CN.claimSound(sEnv);
    check('storage lock: a hidden silent tab neither plays nor writes its timestamp', sHidden === false && st2.getItem('portal_chat_sound_last') === null, [sHidden, st2.getItem('portal_chat_sound_last')]);
    const sVisible = await CN.claimSound({ ...sEnv, document: { hidden: false } });
    check('storage lock: a visible tab plays and writes it', sVisible === true && st2.getItem('portal_chat_sound_last') === String(NOW));
    const sRun = await CN.claimSound({ ...sEnv, now: () => NOW + 5000, audioState: 'running' });
    check('storage lock: a hidden tab with a running context plays', sRun === true);
  }

  // sound is made with WebAudio (nothing fetched)
  const made = { osc: 0, resumed: 0 };
  class FakeCtx {
    constructor() { this.state = 'suspended'; this.currentTime = 0; this.destination = {}; }
    resume() { made.resumed++; this.state = 'running'; }
    createOscillator() { made.osc++; return { frequency: {}, connect() {}, start() {}, stop() {} }; }
    createGain() { return { gain: { setValueAtTime() {}, exponentialRampToValueAtTime() {} }, connect() {} }; }
  }
  const win = { AudioContext: FakeCtx };
  const played = await CN.playSound({ storage: store(), navigator: {}, window: win, now: () => NOW, date: at(12, 0) });
  check('playSound makes oscillator tones and resumes a suspended context', played === true && made.osc === 2 && made.resumed >= 1, JSON.stringify(made));
  const quietStore = store();
  CN.writeSoundSettings(quietStore, { enabled: true, quiet: true, start: '22:00', end: '07:00' });
  const before = made.osc;
  const silent = await CN.playSound({ storage: quietStore, navigator: {}, window: win, now: () => NOW + 99999, date: at(23, 30) });
  check('no tone during quiet hours', silent === false && made.osc === before);
  const src = fs.readFileSync(process.argv[3], 'utf8');
  check('the sound code fetches nothing and loads no file', !/fetch\(|XMLHttpRequest|new Audio\(|https?:\/\//.test(src.replace(/\/\*[\s\S]*?\*\//, '')));

  // the desktop alert names the channel of the frame, not the one on screen
  const alert = CN.channelAlert({ channel: 'lobby', channel_id: 7, username: 'bob', message: 'hi' }, []);
  check('alert names the frame channel and carries a per-channel tag', alert.title.startsWith('#lobby') && alert.tag === 'portal-channel-7'
        && alert.channel === 'lobby', JSON.stringify(alert));
  check('a frame without a channel makes no alert', CN.channelAlert({ username: 'x', message: 'y' }, []) === null);

  // star migration
  const chans = [{ id: 1, name: 'general', notify_level: null }, { id: 2, name: 'dev', notify_level: null }, { id: 3, name: 'set', notify_level: 'none' }];
  const ms = store({ portal_notif_channels: JSON.stringify(['general', 'dev', 'gone', 'set']) });
  const puts = [];
  const n1 = await CN.migrateStars(ms, chans, async (id, body) => { puts.push([id, body.level]); return id !== 2; });
  check('starred channels become level All once; a failure stays for next time; unknown and chosen ones are dropped',
        n1 === 1 && JSON.stringify(puts.sort()) === JSON.stringify([[1, 'all'], [2, 'all']]) && ms.getItem('portal_notif_channels') === '["dev"]', JSON.stringify([n1, puts, ms.getItem('portal_notif_channels')]));
  const n2 = await CN.migrateStars(ms, chans, async () => true);
  check('a second run finishes the leftover and removes the key', n2 === 1 && ms.getItem('portal_notif_channels') === null);
  const none = await CN.migrateStars(store(), chans, async () => { throw new Error('must not be called'); });
  check('nothing starred: nothing to do', none === 0);

  // page handlers
  const calls = { appended: 0, renders: 0, played: 0, desktop: [], reconcile: 0 };
  const channelsList = [{ id: 1, name: 'lobby', notify_level: null, muted_until: 0 },
                        { id: 2, name: 'quiet', notify_level: 'all', muted_until: NOW / 1000 + 3600 },
                        { id: 3, name: 'ment', notify_level: 'mentions', muted_until: 0 },
                        { id: 4, name: 'loud', notify_level: 'all', muted_until: 0 }];
  const sandbox = {
    ChatNotify: { ...CN, isMuted: (c) => CN.isMuted(c, NOW), badgeMode: (c) => CN.badgeMode(c, NOW), alertWanted: (c, m) => CN.alertWanted(c, m, NOW) },
    channelsList, currentChannel: 'general', currentView: 'channel', currentUser: { id: 5 }, pendingJoin: null,
    unreadCounts: new Map(), unreadMentions: new Map(),
    appendLiveMessage: () => calls.appended++, renderChannels: () => calls.renders++, reconcileChannels: () => calls.reconcile++,
    _playChatSound: () => calls.played++, _pageInView: () => false,
    _showChannelAlert: (a) => calls.desktop.push(a.title + '|' + a.tag), _dropChannelAlertFor: () => {}, document: {}, console,
  };
  vm.createContext(sandbox);
  vm.runInContext([fn('bumpChannelUnread'), fn('onChannelActivity'), fn('onChannelMessageFrame'), fn('onMentionNotification')].join('\n') +
                  '\nthis.api = { bumpChannelUnread, onChannelActivity, onChannelMessageFrame, onMentionNotification };', sandbox);
  const api = sandbox.api;
  api.onChannelActivity({ type: 'channel_activity', channel_id: 1 });
  api.onChannelActivity({ type: 'channel_activity', channel_id: 1 });
  check('activity in a channel not joined raises its badge live', sandbox.unreadCounts.get('lobby') === 2 && calls.renders === 2);
  check('a default channel makes no sound', calls.played === 0);
  api.onChannelActivity({ type: 'channel_activity', channel_id: 2 });
  check('a muted channel gets no badge and no sound', !sandbox.unreadCounts.has('quiet') && calls.played === 0);
  api.onChannelActivity({ type: 'channel_activity', channel_id: 4 });
  check('a channel set to All gets badge, sound and a desktop alert for itself',
        sandbox.unreadCounts.get('loud') === 1 && calls.played === 1 && calls.desktop[0] === '#loud|portal-channel-4', JSON.stringify(calls));
  api.onChannelActivity({ type: 'channel_activity', channel_id: 99 });
  check('an unknown channel id refreshes the list', calls.reconcile === 1);
  sandbox.currentChannel = 'lobby';
  api.onChannelActivity({ type: 'channel_activity', channel_id: 1 });
  check('activity for the channel on screen is ignored', sandbox.unreadCounts.get('lobby') === 2);
  sandbox.currentChannel = 'general';
  // mentions
  api.onMentionNotification({ type: 'mention', data: { channel_id: 3, message_id: 9 } });
  check('a mention raises the badge of a Mentions channel and plays', sandbox.unreadMentions.get('ment') === 1 && calls.played === 2);
  api.onMentionNotification({ type: 'mention', data: { channel_id: 2, message_id: 9 } });
  check('a mention in a muted channel still plays but shows no badge', !sandbox.unreadCounts.has('quiet') && !sandbox.unreadMentions.has('quiet') && calls.played === 3);
  // the desktop notification bug: the frame of a room the socket is leaving
  const desktopBefore = calls.desktop.length, appendedBefore = calls.appended;
  sandbox.currentChannel = 'general';
  sandbox.pendingJoin = 'general';        // the join of 'general' was sent, its channel_info has not come
  api.onChannelMessageFrame({ type: 'message', id: 1, user_id: 8, username: 'bob', message: 'from the old room', channel: 'loud', channel_id: 4 });
  check('a frame of another room is not shown in the channel on screen', calls.appended === appendedBefore);
  check('its alert names its own channel, never the one on screen', calls.desktop.length === desktopBefore + 1
        && calls.desktop[desktopBefore].startsWith('#loud') && !calls.desktop[desktopBefore].includes('general'), calls.desktop.join(';'));
  sandbox.pendingJoin = null;
  // no switch on its way: a frame whose channel name differs (a rename, another spelling) is still shown
  api.onChannelMessageFrame({ type: 'message', id: 3, user_id: 8, username: 'bob', message: 'renamed room', channel: 'Renamed', channel_id: 9 });
  check('outside a switch a frame is shown whatever its channel name says', calls.appended === appendedBefore + 1);
  calls.appended--;
  sandbox.currentChannel = 'loud';
  api.onChannelMessageFrame({ type: 'message', id: 2, user_id: 5, username: 'me', message: 'mine', channel: 'loud', channel_id: 4 });
  check('own messages never alert', calls.desktop.length === desktopBefore + 1 && calls.appended === appendedBefore + 1);

  // 140: the list is drawn again when a timed mute ends
  {
    let clock = NOW, seq = 0;
    const pending = new Map();
    const rs = { renders: 0, last: null };
    const sb = {
      Date: { now: () => clock },
      setTimeout: (f, ms) => { const id = ++seq; pending.set(id, { f, at: clock + ms, ms }); return id; },
      clearTimeout: (id) => pending.delete(id),
      channelsList: null,
      renderChannels: (list) => { rs.renders++; rs.last = list; sb.channelsList = list; sb.scheduleMuteRedraw(list); },
      Number, Math,
    };
    vm.createContext(sb);
    vm.runInContext('var _muteRedrawTimer = null;\n' + fn('scheduleMuteRedraw') + '\nthis.scheduleMuteRedraw = scheduleMuteRedraw;', sb);
    const list = [{ id: 1, name: 'a', muted_until: 0 }, { id: 2, name: 'b', muted_until: NOW / 1000 + 600 },
                  { id: 3, name: 'c', muted_until: NOW / 1000 + 60 }, { id: 4, name: 'd', muted_until: NOW / 1000 - 5 }];
    sb.channelsList = list;
    sb.scheduleMuteRedraw(list);
    check('one timer is set, for the nearest future end of a mute', pending.size === 1 && [...pending.values()][0].ms >= 60000 && [...pending.values()][0].ms < 62000,
          JSON.stringify([...pending.values()].map(p => p.ms)));
    sb.scheduleMuteRedraw(list);
    check('scheduling again clears the old timer', pending.size === 1);
    sb.scheduleMuteRedraw([{ id: 1, muted_until: 0 }, { id: 4, muted_until: NOW / 1000 - 5 }]);
    check('no mute running: no timer', pending.size === 0);
    sb.scheduleMuteRedraw(list);
    clock += 61000;
    const due = [...pending.entries()].filter(([, t]) => t.at <= clock);
    due.forEach(([id, t]) => { pending.delete(id); t.f(); });
    check('when the mute ends the list is drawn again', rs.renders === 1 && rs.last === list, rs.renders);
    check('and the next mute gets its own timer', pending.size === 1 && [...pending.values()][0].at > clock);
    sb.scheduleMuteRedraw([{ id: 1, muted_until: clock / 1000 + 10 * 86400 }]);
    check('a far end is capped to the largest timer delay', [...pending.values()].every(t => t.ms <= 2147483647));
  }

  // 143: one mention in an All channel gives one desktop notification, not two
  {
    let clock = NOW;
    const made = [];
    class FakeNotification { constructor(title, o) { this.title = title; this.tag = o.tag; this.closed = false; made.push(this); } close() { this.closed = true; } }
    const timers = [];
    const chans = [{ id: 4, name: 'loud', notify_level: 'all', muted_until: 0 }, { id: 5, name: 'other', notify_level: 'all', muted_until: 0 }];
    const sb = {
      Notification: FakeNotification, NotificationBell: { _isEnabled: () => true }, window: { focus() {} }, switchChannel() {},
      Date: { now: () => clock }, setTimeout: (f, ms) => timers.push([f, ms]),
      channelsList: chans, currentChannel: 'general', currentView: 'channel', currentUser: { id: 5 }, pendingJoin: null,
      unreadCounts: new Map(), unreadMentions: new Map(), console,
      ChatNotify: { ...CN, isMuted: (c) => CN.isMuted(c, NOW), badgeMode: (c) => CN.badgeMode(c, NOW), alertWanted: (c, m) => CN.alertWanted(c, m, NOW) },
      appendLiveMessage() {}, renderChannels() {}, reconcileChannels() {}, _playChatSound() {}, _pageInView: () => false,
    };
    vm.createContext(sb);
    vm.runInContext('var _channelAlerts = new Map();\n' + [fn('_dropChannelAlertFor'), fn('_showChannelAlert'), fn('bumpChannelUnread'),
                    fn('onChannelActivity'), fn('onChannelMessageFrame'), fn('onMentionNotification')].join('\n') +
                    '\nthis.api = { onChannelActivity, onChannelMessageFrame, onMentionNotification };', sb);
    const open = () => made.filter(n => !n.closed).length;
    const mention = (cid, mid) => sb.api.onMentionNotification({ type: 'mention', data: { channel_id: cid, message_id: mid } });
    // a room not joined: the activity alert, then the mention notification (portal.js shows its own)
    sb.api.onChannelActivity({ type: 'channel_activity', channel_id: 4 });
    check('the activity alert of an All channel is shown first', made.length === 1 && made[0].tag === 'portal-channel-4' && open() === 1);
    clock += 300;
    mention(4, 90);
    check('a mention notification for that channel takes the channel alert away', open() === 0, open());
    // the room the socket is in: the message frame, then the mention notification of an @everyone
    made.length = 0;
    sb.currentChannel = 'loud';
    sb.api.onChannelMessageFrame({ type: 'message', id: 91, user_id: 8, username: 'bob', message: '@everyone hi', channel: 'loud', channel_id: 4 });
    check('the frame of the open room raised the channel alert', made.length === 1 && open() === 1);
    clock += 300;
    mention(4, 91);
    check('the mention notification of the same message leaves none of the channel alerts', open() === 0, open());
    // no mention notification follows (a direct mention of a member who is in the room): the alert stays
    made.length = 0;
    sb.api.onChannelMessageFrame({ type: 'message', id: 92, user_id: 8, username: 'bob', message: '@me hi', channel: 'loud', channel_id: 4 });
    check('without a mention notification the channel alert stays', made.length === 1 && open() === 1);
    // a mention in another channel does not touch it
    mention(5, 93);
    check('a mention of another channel leaves it', open() === 1);
    // a late mention notification (more than 5 s later) is another event
    clock += 6000;
    mention(4, 94);
    check('a mention long after the alert does not close it', open() === 1);
  }

  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'harness ran', ok: false, detail: e.stack })); });

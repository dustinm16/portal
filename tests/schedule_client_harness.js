// Runs static/js/portal.js and then static/js/stream-schedule.js the way a browser does: two classic scripts in one
// global scope (vm.runInContext), sharing only the global object, against a small fake DOM and a scripted fetch.
// usage: node schedule_client_harness.js <portal.js> <stream-schedule.js>
'use strict';
const fs = require('fs');
const vm = require('vm');
const results = [];
const setTimeout_real = setTimeout;
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

class N {
  constructor(tag) { this.tagName = String(tag).toUpperCase(); this.children = []; this.attrs = {}; this.listeners = {}; this.value = ''; this.disabled = false; this.style = {}; this.className = ''; this.checked = false; }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  async click() { for (const f of (this.listeners.click || [])) await f({}); }
  set textContent(v) { this.children = v === '' ? [] : [{ tagName: '#text', text: String(v) }]; }
  get textContent() { return this.children.map(c => c.tagName === '#text' ? c.text : c.textContent).join(''); }
  all() { return [this].concat(...this.children.filter(c => c.all).map(c => c.all())); }
  find(pred) { return this.all().filter(pred); }
}
const buttonWith = (root, text) => root.find(n => n.tagName === 'BUTTON' && n.textContent.indexOf(text) === 0)[0];

(async () => {
  const calls = [];
  let answers = [];
  const timers = [];
  const body = new N('BODY');
  const ctx = {
    document: { readyState: 'complete', head: new N('HEAD'), body, getElementById: () => null, createElement: t => new N(t),
                addEventListener() {}, querySelector: () => null, querySelectorAll: () => [] },
    location: { protocol: 'https:', host: 'portal.test', pathname: '/watch/7', href: 'https://portal.test/watch/7' },
    localStorage: { getItem: () => null, setItem() {} }, navigator: {},
    setTimeout: () => 0, setInterval: (f) => { timers.push(f); return timers.length; }, clearTimeout() {}, clearInterval() {},
    console,
    fetch: async (url, init) => {
      calls.push({ url, method: init && init.method, body: init && init.body ? JSON.parse(init.body) : null });
      const a = answers.shift() || { status: 200, data: {} };
      return { ok: a.status >= 200 && a.status < 300, status: a.status, json: async () => a.data };
    },
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'portal.js' });
  vm.runInContext(fs.readFileSync(process.argv[3], 'utf8'), ctx, { filename: 'stream-schedule.js' });
  const SS = ctx.StreamSchedule;
  check('stream-schedule.js publishes window.StreamSchedule after portal.js', SS && typeof SS.mountWatch === 'function' && ctx.Portal && typeof ctx.Portal.toast === 'function');
  const take = () => { const c = calls.slice(); calls.length = 0; return c; };

  check('countdownText: now, seconds, hours, days', SS.countdownText(0) === 'Starting now' && SS.countdownText(-5) === 'Starting now'
    && SS.countdownText(65) === '0:01:05' && SS.countdownText(3 * 3600 + 62) === '3:01:02' && SS.countdownText(86400 + 3600) === '1 day 1:00:00'
    && SS.countdownText(2 * 86400) === '2 days 0:00:00', [0, 65, 86400 + 3600].map(SS.countdownText).join('|'));

  // ---- the watch page
  const nowSec = Math.floor(Date.now() / 1000);
  const item = { entry_id: 3, stream_id: 7, title: '<img src=x onerror=alert(1)>', start: nowSec + 3 * 3600, interested: false, duration_min: 60 };
  const stream = { id: 7, user_id: 11 };
  answers = [{ status: 200, data: { now: nowSec, next: [item] } }];
  let holder = new N('DIV');
  const mounted = await SS.mountWatch(holder, stream, { id: 5 });
  check('watch: it asks for this stream\'s schedule', calls[0].url === '/api/streams/7/schedule' && calls[0].method === 'GET');
  check('watch: the title is text, never markup', holder.find(n => n.tagName === 'IMG').length === 0 && holder.textContent.indexOf('<img src=x onerror=alert(1)>') >= 0);
  check('watch: the countdown shows about 3 hours', /^[23]:\d\d:\d\d$/.test(holder.find(n => n.className === 'schedule-countdown')[0].textContent), holder.textContent);
  const btn = buttonWith(holder, 'Interested');
  check('watch: a signed-in member who is not the streamer gets the Interested toggle', !!btn && btn.getAttribute('aria-pressed') === 'false');
  take();
  answers = [{ status: 200, data: { interested: true } }];
  await btn.click();
  let c = take();
  check('watch: tapping it POSTs to the occurrence and shows the pressed state', c.length === 1 && c[0].method === 'POST'
    && c[0].url === `/api/streams/7/schedule/3/rsvp/${item.start}` && btn.getAttribute('aria-pressed') === 'true' && /reminder set/.test(btn.textContent), JSON.stringify(c));
  answers = [{ status: 200, data: { interested: false } }];
  await btn.click();
  c = take();
  check('watch: tapping again DELETEs it', c[0].method === 'DELETE' && btn.getAttribute('aria-pressed') === 'false');
  answers = [{ status: 404, data: { error: 'Stream not found' } }];
  await btn.click();
  check('watch: a refused change leaves the button as it was', btn.getAttribute('aria-pressed') === 'false');
  mounted.stop();
  for (const [label, user, s] of [['the streamer', { id: 11 }, stream], ['a visitor (no user)', null, stream]]) {
    answers = [{ status: 200, data: { now: nowSec, next: [item] } }];
    const h = new N('DIV');
    const m = await SS.mountWatch(h, s, user);
    check(`watch: ${label} sees the countdown and no toggle`, !!m && h.textContent.indexOf('Next stream') >= 0 && !buttonWith(h, 'Interested'));
    m.stop();
  }
  // once the start has passed the route refuses a mark, so the toggle is hidden (at once, or when the countdown reaches zero)
  answers = [{ status: 200, data: { now: nowSec, next: [{ ...item, start: nowSec - 5 }] } }];
  const late = new N('DIV');
  const lateM = await SS.mountWatch(late, stream, { id: 5 });
  const lateRow = late.find(n => n.className === 'schedule-mark')[0];
  check('watch: an occurrence that began a moment ago shows "Starting now" and no toggle',
    late.textContent.indexOf('Starting now') >= 0 && !!lateRow && lateRow.style.display === 'none', late.textContent);
  lateM.stop();
  answers = [{ status: 200, data: { now: nowSec, next: [{ ...item, start: nowSec + 1 }] } }];
  const soon = new N('DIV');
  const soonM = await SS.mountWatch(soon, stream, { id: 5 });
  const soonRow = soon.find(n => n.className === 'schedule-mark')[0];
  check('watch: with a second to go the toggle is still there', !!soonRow && soonRow.style.display !== 'none');
  await new Promise(r => setTimeout_real(r, 1300));
  timers[timers.length - 1]();
  check('watch: when the countdown reaches zero the toggle goes', soonRow.style.display === 'none' && soon.textContent.indexOf('Starting now') >= 0, soon.textContent);
  soonM.stop();
  answers = [{ status: 404, data: {} }];
  const none = new N('DIV');
  check('watch: a stream the member may not see shows nothing', (await SS.mountWatch(none, stream, { id: 5 })) === null && none.children.length === 0);
  answers = [{ status: 200, data: { now: nowSec, next: [] } }];
  check('watch: no schedule, nothing drawn', (await SS.mountWatch(new N('DIV'), stream, { id: 5 })) === null);

  // ---- the Upcoming strip
  answers = [{ status: 200, data: { occurrences: [
    { entry_id: 3, stream_id: 7, stream_name: 's', streamer: 'Anna', title: 'Show', start: nowSec + 600, recurring: true, interested: true },
    { entry_id: 4, stream_id: 8, stream_name: 't', streamer: 'Me', title: 'Mine', start: nowSec + 900, recurring: false, interested: false, interested_count: 4 }] } }];
  const strip = new N('DIV');
  await SS.mountUpcoming(strip);
  check('strip: one card per occurrence with a link to the watch page', strip.find(n => n.tagName === 'A').map(a => a.attrs.href).join() === '/watch/7,/watch/8');
  check('strip: the link to the stream is a theme button', strip.find(n => n.tagName === 'A').every(a => /(^| )btn( |$)/.test(a.className) && /btn-secondary/.test(a.className)));
  check('strip: the member\'s own state shows; the owner of a stream sees a count and no toggle',
    strip.find(n => n.tagName === 'BUTTON').length === 1 && strip.textContent.indexOf('4 interested') >= 0
    && strip.find(n => n.tagName === 'BUTTON')[0].getAttribute('aria-pressed') === 'true');
  answers = [{ status: 200, data: { occurrences: [] } }];
  const empty = new N('DIV');
  await SS.mountUpcoming(empty);
  check('strip: hidden when nothing is scheduled', empty.style.display === 'none');

  // ---- the owner's editor
  const owner = { status: 200, data: { entries: [{ id: 3, title: 'Show', start: '2026-12-04T21:00', tz: 'Europe/Berlin', duration_min: 60, recurrence: 'weekly',
      next: [{ start: nowSec + 100, interested_count: 2 }], cancelled: [nowSec + 9999] }],
    suggestion: { entry_id: 3, start: nowSec, title: 'Friday show' }, limits: { title: 100 } } };
  take();
  answers = [owner];
  const ed = new N('DIV');
  let applied = [];
  await SS.mountOwner(ed, 7, (t) => { applied.push(t); });
  check('owner: the suggestion is offered, with a button, not applied', ed.textContent.indexOf('Friday show') >= 0 && !!buttonWith(ed, 'Use this title') && take().length === 1);
  check('owner: a count of interested members is shown and no names', ed.textContent.indexOf('2 interested') >= 0);
  answers = [{ status: 200, data: {} }, { status: 200, data: {} }, owner];
  await buttonWith(ed, 'Use this title').click();
  c = take();
  check('owner: Use this title PUTs the name, then clears the suggestion', c[0].method === 'PUT' && c[0].url === '/api/streams/7' && c[0].body.name === 'Friday show'
    && c[1].method === 'DELETE' && c[1].url === '/api/streams/7/schedule/suggestion' && applied.length === 1 && applied[0] === 'Friday show', JSON.stringify(c) + JSON.stringify(applied));
  answers = [{ status: 200, data: {} }, owner];
  await buttonWith(ed, 'Cancel this one').click();
  c = take();
  check('owner: cancelling one occurrence POSTs its start', c[0].method === 'POST' && c[0].url === `/api/streams/7/schedule/3/cancel/${nowSec + 100}`, JSON.stringify(c));
  answers = [{ status: 200, data: {} }, owner];
  await buttonWith(ed, 'Restore').click();
  c = take();
  check('owner: restoring DELETEs the cancellation', c[0].method === 'DELETE' && /\/cancel\/\d+$/.test(c[0].url));
  const inputs = ed.find(n => n.tagName === 'INPUT');
  const [title, start, tz, dur, weekly] = inputs;
  title.value = 'New show'; start.value = '2026-12-11T21:00'; tz.value = 'Europe/Berlin'; dur.value = '90'; weekly.checked = true;
  answers = [{ status: 201, data: {} }, owner];
  await buttonWith(ed, 'Add to the schedule').click();
  c = take();
  check('owner: the form POSTs title, start, zone, minutes and weekly', c[0].method === 'POST' && c[0].url === '/api/streams/7/schedule'
    && JSON.stringify(c[0].body) === JSON.stringify({ title: 'New show', start: '2026-12-11T21:00', tz: 'Europe/Berlin', duration_min: 90, recurrence: 'weekly' }), JSON.stringify(c[0].body));
  // the form: styled with the stream settings' form classes, every label linked to its field, the start's zone named correctly
  const labels = ed.find(n => n.tagName === 'LABEL');
  const ids = ed.find(n => n.tagName === 'INPUT').map(n => n.id);
  check('owner: every label has a "for" naming exactly one field of the form and the ids are unique',
    labels.length === 5 && labels.every(l => ids.filter(i => i === l.getAttribute('for')).length === 1) && new Set(ids).size === ids.length && ids.every(Boolean), JSON.stringify(ids));
  check('owner: each field sits in a form-group row with its label, the checkbox in a checkbox-label',
    ed.find(n => n.className === 'form-group').length === 5 && ed.find(n => n.className === 'checkbox-label').length === 1
    && ed.find(n => n.className === 'form-group').every(g => g.find(n => n.tagName === 'LABEL').length === 1 && g.find(n => n.tagName === 'INPUT').length === 1));
  check('owner: the start is labelled as read in the zone chosen in the zone field, not "your time zone"',
    ed.textContent.indexOf('Start (read in the time zone chosen below)') >= 0 && ed.textContent.indexOf('your time zone') < 0);
  answers = [{ status: 200, data: {} }, owner];
  await buttonWith(ed, 'Delete the whole entry').click();
  check('owner: Delete removes the entry', take()[0].url === '/api/streams/7/schedule/3');
  answers = [{ status: 200, data: { entries: [
    { id: 4, title: 'Lost zone', start: '2026-12-04T21:00', tz: 'Mars/Olympus', duration_min: 60, recurrence: null, next: [], cancelled: [], problem: 'time zone no longer available' },
    { id: 5, title: 'Fine', start: '2026-12-05T21:00', tz: 'Europe/Berlin', duration_min: 60, recurrence: null, next: [], cancelled: [] }], suggestion: null, limits: { title: 100 } } }];
  const ed2 = new N('DIV');
  await SS.mountOwner(ed2, 7, () => {});
  take();
  check('owner: an entry whose zone the host lost says "time zone no longer available", once, and the other entry does not',
    ed2.textContent.split('time zone no longer available').length === 2 && ed2.textContent.indexOf('Lost zone') >= 0
    && ed2.textContent.indexOf('Fine') >= 0, ed2.textContent);

  // ---- the calendar link
  answers = [{ status: 200, data: { active: false } }];
  const feed = new N('DIV');
  await SS.mountFeed(feed);
  check('feed: with no link the button says Create link', !!buttonWith(feed, 'Create link') && !buttonWith(feed, 'Revoke'));
  check('feed: the warning about proxy logs is next to the buttons', /proxies/.test(feed.textContent) && /log an address/.test(feed.textContent) && /regenerate/i.test(feed.textContent));
  const secret = 'https://portal.test/api/streams/schedule/feed/sf_SECRET.ics';
  answers = [{ status: 200, data: { active: true, url: secret } }];
  take();
  await buttonWith(feed, 'Create link').click();
  check('feed: Create POSTs and shows the address once, with Regenerate and Revoke', take()[0].method === 'POST'
    && feed.find(n => n.tagName === 'INPUT')[0].value === secret && !!buttonWith(feed, 'Regenerate') && !!buttonWith(feed, 'Revoke') && /proxies/.test(feed.textContent));
  answers = [{ status: 200, data: { active: false } }];
  await buttonWith(feed, 'Revoke').click();
  check('feed: Revoke DELETEs and forgets the address', take()[0].method === 'DELETE' && feed.find(n => n.tagName === 'INPUT').length === 0 && feed.textContent.indexOf('SECRET') < 0);

  console.log(results.map(r => 'RESULT ' + JSON.stringify(r)).join('\n'));
})().catch(e => { console.log('RESULT ' + JSON.stringify({ name: 'the harness ran', ok: false, detail: String(e && e.stack || e) })); });

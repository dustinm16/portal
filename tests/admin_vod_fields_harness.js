// Runs the retention form code of static/admin.html (render and save) under Node against small fakes
// (a fake document, Portal.fetch and toast). Used by tests/test_admin_vod_fields.py.
// usage: node admin_vod_fields_harness.js <admin.html>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');
const html = fs.readFileSync(process.argv[2], 'utf8');
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

const i = html.indexOf('function renderRetentionConfig() {');
const j = html.indexOf('async function runCleanupNow()', i);
if (i < 0 || j < 0) throw new Error('cannot find the retention form code');
const src = 'var retentionConfig = {};\n' + html.slice(i, j);

const els = {};
const getEl = (id) => (els[id] = els[id] || { id, value: '', checked: false, textContent: '', innerHTML: '', focused: 0, focus() { this.focused += 1; } });
const calls = [];
const toasts = [];
let answer = { status: 200, data: {} };
const sandbox = {
  console, JSON, Number, isFinite, parseInt, isNaN,
  document: { getElementById: getEl },
  Portal: {
    fetch: async (url, o) => { calls.push({ url, body: JSON.parse(o.body) }); return { ok: answer.status < 300, json: async () => answer.data }; },
    toast: (m, k) => toasts.push([m, k]),
  },
};
vm.createContext(sandbox);
vm.runInContext(src, sandbox);
const CFG = { retention_chat_days: '7', retention_chat_max_days: '3650', retention_dm_days: '30', retention_notifications_days: '30',
  retention_activity_max: '500', retention_service_logs_max: '1000', retention_device_metrics_days: '14', retention_recordings_days: '30',
  recording_max_total_mb: '2048', vod_min_free_gb: '1', vod_max_backlog_gb: '2', vod_play_cache_mb: '512', vod_orphan_max_age_days: '14',
  retention_security_events_days: '180', cleanup_interval_hours: '6', auto_vacuum: 'true' };
const IDS = { 'ret-vod-min-free': 'vod_min_free_gb', 'ret-vod-backlog': 'vod_max_backlog_gb', 'ret-vod-play-cache': 'vod_play_cache_mb', 'ret-vod-orphan-age': 'vod_orphan_max_age_days' };

function fill(v) { for (const id of Object.keys(IDS)) getEl(id).value = v[id] === undefined ? String(CFG[IDS[id]]) : String(v[id]); }
async function save(v) {
  fill(v || {}); calls.length = 0; toasts.length = 0;
  await sandbox.saveRetentionConfig();
  return calls[0] || null;
}
const err = (id) => getEl(id + '-err').textContent;

(async () => {
  sandbox.retentionConfig = Object.assign({}, CFG);
  vm.runInContext('retentionConfig = ' + JSON.stringify(CFG), sandbox);
  const done = () => { answer = { status: 200, data: { updated: true, config: Object.assign({}, CFG) } }; };
  done();

  let c = await save();
  check('the stored values are sent as numbers', c && c.body.vod_min_free_gb === 1 && c.body.vod_max_backlog_gb === 2 && c.body.vod_play_cache_mb === 512 && c.body.vod_orphan_max_age_days === 14, JSON.stringify(c));

  c = await save({ 'ret-vod-play-cache': '0.5' });
  check('a decimal in the playback cache field is refused instead of becoming 0 (no request)', c === null && /whole number/.test(err('ret-vod-play-cache')), err('ret-vod-play-cache'));
  check('the message is next to the field and the field gets the focus', getEl('ret-vod-play-cache').focused === 1 && err('ret-vod-min-free') === '');
  c = await save({ 'ret-vod-orphan-age': '1.5' });
  check('a decimal number of days is refused', c === null && /whole number/.test(err('ret-vod-orphan-age')));
  c = await save({ 'ret-vod-play-cache': '-1', 'ret-vod-min-free': '-0.5' });
  check('negative numbers are refused, each with its own message', c === null && /negative/.test(err('ret-vod-play-cache')) && /negative/.test(err('ret-vod-min-free')));
  c = await save({ 'ret-vod-backlog': '', 'ret-vod-orphan-age': 'abc' });
  check('an empty or non-numeric value is refused, not replaced by a default', c === null && /number/.test(err('ret-vod-backlog')) && /number/.test(err('ret-vod-orphan-age')));
  c = await save({ 'ret-vod-backlog': '1e999' });
  check('a number too large to be a number is refused', c === null && /number/.test(err('ret-vod-backlog')));
  c = await save({ 'ret-vod-min-free': '0.5', 'ret-vod-backlog': '0.25' });
  check('the gigabyte fields accept fractions', c && c.body.vod_min_free_gb === 0.5 && c.body.vod_max_backlog_gb === 0.25 && err('ret-vod-min-free') === '' && err('ret-vod-play-cache') === '', JSON.stringify(c));
  c = await save({ 'ret-vod-min-free': '0', 'ret-vod-play-cache': '0', 'ret-vod-orphan-age': '0' });
  check('zero is allowed (switches a check off)', c && c.body.vod_min_free_gb === 0 && c.body.vod_play_cache_mb === 0 && c.body.vod_orphan_max_age_days === 0);

  // the form is drawn again from the configuration the server returns
  answer = { status: 200, data: { updated: true, config: Object.assign({}, CFG, { vod_play_cache_mb: '1000000', vod_min_free_gb: '0.5' }) } };
  await save({ 'ret-vod-play-cache': '99999999' });
  const form = getEl('retention-config').innerHTML;
  check('after saving the form shows what the server kept, not what was typed',
    /id="ret-vod-play-cache" value="1000000"/.test(form) && /id="ret-vod-min-free" value="0.5"/.test(form), form.slice(0, 80));
  check('the saved toast is shown', toasts.some((t) => /saved/.test(t[0])));
  answer = { status: 400, data: { error: 'nope' } };
  getEl('retention-config').innerHTML = 'untouched';
  await save();
  check('a refused save does not redraw the form and says why', getEl('retention-config').innerHTML === 'untouched' && toasts.some((t) => t[1] === 'error'));
  check('the form has an error slot per VOD field and no inline handler on them',
    ['ret-vod-min-free', 'ret-vod-backlog', 'ret-vod-play-cache', 'ret-vod-orphan-age'].every((id) => form.includes('id="' + id + '-err"')) && !/<(input|div)[^>]*ret-vod[^>]*onclick/.test(form));
  process.stdout.write(results.map((r) => 'RESULT ' + JSON.stringify(r)).join('\n') + '\n');
})().catch((e) => { console.log('RESULT ' + JSON.stringify({ name: 'harness crashed', ok: false, detail: e.stack })); });

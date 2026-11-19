// Runs the Cloudflare ranges panel code of static/admin.html under Node against small fakes
// (document, Portal.fetch, confirm). Used by tests/test_cf_panel.py.
//
// usage: node cf_panel_harness.js <admin.html>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(process.argv[2], 'utf8');
const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) });
}

function slice(src, from, to) {
  const i = src.indexOf(from);
  const j = src.indexOf(to, i);
  if (i < 0 || j < 0) throw new Error('cannot find ' + from);
  return src.slice(i, j);
}

const escSrc = slice(html, 'function escapeHtml(text) {', '\n        }\n') + '\n}\n';
const panelSrc = slice(html, 'async function loadCfRanges()', '// ===== DATA RETENTION =====');
const trustSrc = slice(html, 'async function loadNetworkTrust()', 'let neverBanState');

const handlers = {};
const body = { innerHTML: '' };
const trustBody = { innerHTML: '' };
const calls = [];
let confirmAnswer = true;
let confirmMessages = [];
let nextResponse = { ok: true, json: async () => ({}) };
const toasts = [];

const context = {
  document: {
    getElementById: (id) => (id === 'cfranges-body' ? body : id === 'network-trust-body' ? trustBody : null),
    addEventListener: (type, fn) => { (handlers[type] = handlers[type] || []).push(fn); },
  },
  Portal: {
    fetch: async (url, opts) => {
      calls.push({ url, opts });
      return url.includes('proxy-trust') ? { ok: false, json: async () => ({}) } : nextResponse;
    },
    toast: (msg, kind) => toasts.push([msg, kind]),
  },
  confirm: (msg) => { confirmMessages.push(msg); return confirmAnswer; },
  loadNetworkTrust: () => {},
  console,
};
vm.createContext(context);
vm.runInContext(escSrc, context);
vm.runInContext(panelSrc, context);
vm.runInContext(trustSrc, context);

async function renderTrust(view) {
  nextResponse = { ok: true, json: async () => view };
  await context.loadNetworkTrust();
  return trustBody.innerHTML;
}

async function render(view) {
  nextResponse = { ok: true, json: async () => view };
  await context.loadCfRanges();
  return body.innerHTML;
}

function click(button, holderId) {
  const holder = { getAttribute: (n) => (n === 'data-cf-pending-id' ? holderId : null) };
  button.closest = (sel) => {
    if (sel === '[data-cfranges-action]') return button;
    if (sel === '[data-cf-pending-id]') return holder;
    return null;
  };
  for (const fn of handlers.click || []) fn({ target: button });
}

const base = {
  enabled: true, source: 'built-in', fetched_at: null, v4: 15, v6: 7, last: null, stage_mode: false,
  saved_list: false, saved_list_applied: false, saved_list_ignored: false,
  saved_list_ignored_reason: null, fetched_in_use_until_restart: false, pending: null,
};

(async () => {
  let out = await render(base);
  check('no pending list: no approval box', !out.includes('waiting for approval') && !out.includes('data-cfranges-action="approve"'));
  check('the reset note says a fetched list returns at the next scheduled refresh',
        out.includes('a fetched list returns at the next scheduled refresh'));

  const pending = {
    id: 'abc123def4567890', fetched_at: '2026-11-19 03:00:00', v4: 23, v6: 7,
    reason: '8 new IPv4 ranges in one refresh; at most 5 are accepted <img src=x onerror=alert(1)>',
    added: ['45.0.0.0/16', '<b>46.0.0.0/16</b>'], removed: ['173.245.48.0/20'], diff_is_current: true,
  };
  out = await render({ ...base, pending });
  check('a pending list shows the box, the reason and both buttons',
        out.includes('waiting for approval') && out.includes('8 new IPv4 ranges') &&
        out.includes('data-cfranges-action="approve"') && out.includes('data-cfranges-action="dismiss"'));
  check('the added and removed ranges are listed with their counts',
        out.includes('Added (2)') && out.includes('45.0.0.0/16') && out.includes('Removed (1)') && out.includes('173.245.48.0/20'));
  check('hostile text in the reason or a range is escaped, never markup',
        !out.includes('<img') && !out.includes('<b>46') && out.includes('&lt;img') && out.includes('&lt;b&gt;'));
  check('a stale difference is flagged', (await render({ ...base, pending: { ...pending, diff_is_current: false } }))
        .includes('has changed since this list was fetched'));
  out = await render({ ...base, pending });

  // clicks
  const approve = { getAttribute: (n) => (n === 'data-cfranges-action' ? 'approve' : null) };
  const dismiss = { getAttribute: (n) => (n === 'data-cfranges-action' ? 'dismiss' : null) };
  calls.length = 0; confirmAnswer = false; confirmMessages = [];
  click(approve, pending.id);
  await new Promise((r) => setTimeout(r, 10));
  check('approve asks for confirmation and sends nothing when it is refused', confirmMessages.length === 1 && calls.length === 0);
  confirmAnswer = true;
  click(approve, pending.id);
  await new Promise((r) => setTimeout(r, 10));
  const approveCall = calls.find((c) => c.url.endsWith('/pending/approve'));
  check('approve posts the id of the list that was shown',
        approveCall && approveCall.opts.method === 'POST' && JSON.parse(approveCall.opts.body).id === pending.id,
        JSON.stringify(calls));
  calls.length = 0; confirmMessages = [];
  click(dismiss, pending.id);
  await new Promise((r) => setTimeout(r, 10));
  const dismissCall = calls.find((c) => c.url.endsWith('/pending/dismiss'));
  check('dismiss posts the id too, without a confirmation',
        dismissCall && JSON.parse(dismissCall.opts.body).id === pending.id && confirmMessages.length === 0);
  calls.length = 0;
  click(approve, '');
  await new Promise((r) => setTimeout(r, 10));
  check('a button without a list id sends nothing', calls.length === 0);

  // why a saved list is ignored
  out = await render({ ...base, saved_list: true, saved_list_ignored: true, saved_list_ignored_reason: 'refresh_off', enabled: true });
  check('refresh off at start (and switched on since): the text says it was off at start, not that the checks failed',
        out.includes('was off when the portal started') && !out.includes('failed the checks'));
  out = await render({ ...base, saved_list: true, saved_list_ignored: true, saved_list_ignored_reason: 'failed_checks', enabled: false });
  check('failed checks (and the refresh switched off since): the text says the checks failed, not that the refresh was off',
        out.includes('failed the checks when the portal started') && !out.includes('was off when the portal started'));
  out = await render({ ...base, saved_list: true, saved_list_ignored: true, saved_list_ignored_reason: 'failed_checks', enabled: true });
  check('failed checks with the refresh on: same text', out.includes('failed the checks when the portal started'));
  out = await render({ ...base });
  check('nothing ignored: neither text', !out.includes('failed the checks') && !out.includes('was off when the portal started'));

  // the result of the last refresh: a failure, a success and a refresh discarded by a reset
  const lastFailed = { ok: false, at: '2026-11-19 03:00:00', message: 'IPv4 list is empty', last_ok_at: '2026-11-12 03:00:00' };
  const lastDiscarded = { ok: false, discarded: true, at: '2026-11-19 03:00:00', last_ok_at: '2026-11-12 03:00:00',
                          message: 'the list was reset while the refresh ran; the fetched result was discarded and comes back at a later scheduled refresh' };
  out = await render({ ...base, last: lastFailed });
  check('settings panel: a failed refresh is shown as failed', out.includes('Last refresh failed'));
  out = await render({ ...base, last: lastDiscarded });
  check('settings panel: a refresh discarded by a reset is not shown as failed',
        !out.includes('Last refresh failed') && out.includes('Last refresh discarded') && out.includes('reset while it ran'), out);
  out = await renderTrust({ ...base, last: lastFailed });
  check('status panel: a failed refresh is shown as failed', out.includes('Last refresh failed'));
  out = await renderTrust({ ...base, last: lastDiscarded });
  check('status panel: a refresh discarded by a reset is not shown as failed',
        !out.includes('Last refresh failed') && out.includes('Last refresh discarded'), out);
  out = await render({ ...base, last: { ok: true, at: '2026-11-19 03:00:00', v4: 15, v6: 7 } });
  check('settings panel: a success is still shown as a success', out.includes('Last refresh: 2026-11-19') && !out.includes('discarded'));

  // the reset confirmation
  confirmMessages = []; calls.length = 0;
  const reset = { getAttribute: (n) => (n === 'data-cfranges-action' ? 'reset' : null) };
  click(reset, '');
  await new Promise((r) => setTimeout(r, 10));
  check('the reset confirmation says a fetched list returns at the next scheduled refresh',
        confirmMessages.length === 1 && confirmMessages[0].includes('returns at the next scheduled refresh'));

  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
})().catch((e) => { console.log('RESULT ' + JSON.stringify({ name: 'harness ran', ok: false, detail: String(e && e.stack || e) })); });

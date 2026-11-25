// Runs the automod rule form code of static/admin.html (config fields and getAutomodConfig) under Node against a
// small fake document. Used by tests/test_automod_words_form.py.
// usage: node automod_words_harness.js <admin.html>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');
const html = fs.readFileSync(process.argv[2], 'utf8');
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

function slice(from, to) {
  const i = html.indexOf(from), j = html.indexOf(to, i);
  if (i < 0 || j < 0) throw new Error('cannot find ' + from);
  return html.slice(i, j);
}
const escSrc = slice('function escapeHtml(text) {', '\n        }\n') + '\n}\n';
const src = escSrc + slice('function updateAutomodConfigFields() {', 'async function submitAutomodRule');

const els = {};
const getEl = (id) => (els[id] = els[id] || { id, value: '', checked: false, innerHTML: '' });
const sandbox = { console, JSON, parseInt, window: {}, document: { getElementById: getEl } };
vm.createContext(sandbox);
vm.runInContext(src, sandbox);

function unescape_(t) { return t.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&'); }
// open the form for a stored rule and return the text of the words field and the help text
function open(config) {
  sandbox.window._amEditConfig = config; sandbox.window._amEditType = 'word_filter';
  getEl('am-type').value = 'word_filter';
  sandbox.updateAutomodConfigFields();
  const h = getEl('am-config-fields').innerHTML;
  const m = h.match(/<textarea id="am-words"[^>]*>([\s\S]*?)<\/textarea>/);
  return { text: m ? unescape_(m[1]) : null, label: (h.match(/<label[^>]*>([^<]*)<\/label>/) || [])[1], help: h };
}
function save(text, mode) {
  getEl('am-type').value = 'word_filter';
  getEl('am-words').value = text; getEl('am-match-mode').value = mode;
  return sandbox.getAutomodConfig();
}
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// a regex with a comma is saved whole and read back unchanged
const rx = save('a{1,3}', 'regex');
check('regex a{1,3} is saved as one pattern', same(rx.words, ['a{1,3}']) && rx.match_mode === 'regex', JSON.stringify(rx));
const back = open({ words: rx.words, match_mode: 'regex' });
check('the saved regex is shown unchanged on edit', back.text === 'a{1,3}\n', JSON.stringify(back.text));
check('saving it again without a change keeps it', same(save(back.text, 'regex').words, ['a{1,3}']));
check('regex patterns on separate lines are separate entries', same(save('a{1,3}\n^x,y$\r\n\n  z  ', 'regex').words, ['a{1,3}', '^x,y$', 'z']));
check('a regex field with no line break is one pattern, commas included', same(save('colou?r,x', 'regex').words, ['colou?r,x']));
// the old comma list keeps working when there is no line break and the rule is not a regex rule
check('contains mode, no line break: comma-separated as before', same(save('foo, bar ,baz,', 'contains').words, ['foo', 'bar', 'baz']));
check('exact mode, no line break: comma-separated as before', same(save('foo,bar', 'exact').words, ['foo', 'bar']));
check('contains mode with line breaks: one entry per line, commas kept', same(save('hello, world\nfoo', 'contains').words, ['hello, world', 'foo']));
check('empty field gives no words', same(save('', 'contains').words, []) && same(save(' \n ', 'regex').words, []));
// edit display
const multi = open({ words: ['spam', 'a{1,3}', 'x'], match_mode: 'regex' });
check('stored words are shown one per line', multi.text === 'spam\na{1,3}\nx', JSON.stringify(multi.text));
check('a stored list of several words round-trips', same(save(multi.text, 'regex').words, ['spam', 'a{1,3}', 'x']));
const lone = open({ words: ['hello, world'], match_mode: 'contains' });
check('a lone stored phrase with a comma survives a save without a change', same(save(lone.text, 'contains').words, ['hello, world']), JSON.stringify(lone.text));
check('one word without a comma has no trailing line break', open({ words: ['spam'], match_mode: 'contains' }).text === 'spam');
check('no stored words show an empty field', open({}).text === '');
check('the label says one per line', /one per line/.test(multi.label), multi.label);
check('the help no longer says a pattern cannot contain a comma', !/cannot contain a comma/.test(multi.help) && /one word or pattern per line/.test(multi.help));
check('other types are untouched: link block list stays comma-separated', (() => {
  getEl('am-type').value = 'link_filter'; getEl('am-blocklist').value = 'a.com, b.com'; getEl('am-blockall').checked = false;
  return same(sandbox.getAutomodConfig().block_list, ['a.com', 'b.com']);
})());

for (const r of results) console.log('RESULT ' + JSON.stringify(r));

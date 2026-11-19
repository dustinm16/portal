// Runs the search block of static/chat.html (suggestion chips, result rendering,
// result click) under Node against a small fake page. Used by
// tests/test_chat_search_client.py.
//
// usage: node chat_search_harness.js <path to chat.html>
// prints one line per check: RESULT {"name":..., "ok":..., "detail":...}
'use strict';
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(process.argv[2], 'utf8');
const a = html.indexOf('// SEARCH-CLIENT-BEGIN');
const b = html.indexOf('// SEARCH-CLIENT-END');
if (a < 0 || b < 0) { console.log('RESULT ' + JSON.stringify({ name: 'search block found', ok: false, detail: 'markers missing' })); process.exit(0); }
const BLOCK = html.slice(a, b);

const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

function el() {
  const e = { style: {}, dataset: {}, children: [], textContent: '', innerHTML: '', value: '', className: '', type: '' };
  e.appendChild = (c) => { e.children.push(c); return c; };
  e.insertAdjacentHTML = (_pos, h) => { e.innerHTML += h; };
  e.querySelectorAll = () => e.children.filter(c => (c.className || '').includes('search-more-btn'));
  e.focus = () => {};
  return e;
}

const els = { 'search-chips': el(), 'search-input': el(), 'search-results-panel': el(), 'search-results-list': el(),
              'search-result-count': el(), 'search-results-note': el(), 'search-scope': el() };
els['search-scope'].value = 'all';
const jumps = [], fetched = [], toasts = [];
let fetchHook = null;
const sandbox = {
  document: { getElementById: (id) => els[id], createElement: () => el() },
  escapeHtml: (t) => String(t == null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'),
  channelsList: [{ id: 1, name: 'general' }, { id: 2, name: 'random' }, { id: 3, name: 'garden' }],
  onlineUsers: new Map([[1, { user_id: 1, username: 'mom' }], [2, { user_id: 2, username: 'bob' }],
                        [3, { user_id: null, username: 'Anonymous', anon_ref: 'abc' }],
                        [4, { user_id: 9, username: 'Anonymous', anonymous: true }]]),
  closeSearchPanel() {}, openDmConversation(id) { jumps.push(['dm', id]); },
  jumpToChannelMessage(c, m) { jumps.push(['channel', c, m]); },
  Portal: { fetch: async (url) => { fetched.push(url); if (fetchHook) return fetchHook(url); return { ok: true, json: async () => ({ results: [], total: 0 }) }; },
            toast: (m) => toasts.push(m) },
  console,
};
vm.createContext(sandbox);
vm.runInContext(BLOCK + '\nthis.api = { searchSuggestions, searchKnownNames, renderSearchChips, applySearchChip, executeSearch, searchResultHtml, renderSearchResults, navigateToSearchResult, loadMoreSearch, searchState: () => searchState };', sandbox);
const api = sandbox.api;
const labels = (x) => x.map(c => c.label).join(',');

check('an empty input offers every operator', labels(api.searchSuggestions('', [], [])) === 'from:,in:,has:link,has:file,has:image,is:pinned,before:,after:');
check('a typed prefix narrows the operators', labels(api.searchSuggestions('dinner ha', [], [])) === 'has:link,has:file,has:image');
check('in: offers channel names from the loaded list', labels(api.searchSuggestions('x in:g', ['general', 'random', 'garden'], [])) === 'general,garden');
check('-in: and -from: keep the minus in the token', api.searchSuggestions('-in:r', ['random'], [])[0].token === '-in:random ');
check('from: offers loaded people', labels(api.searchSuggestions('from:', [], ['mom', 'bob'])) === 'mom,bob');
check('has: offers the three values, is: offers pinned', labels(api.searchSuggestions('has:', [], [])) === 'link,file,image' && labels(api.searchSuggestions('is:p', [], [])) === 'pinned');
check('a complete value offers nothing more', api.searchSuggestions('in:general', ['general'], []).length === 0);
const known = api.searchKnownNames();
check('channel names come from the loaded channel list', known.channels.join() === 'general,random,garden');
check('no chip is made for an anonymous entry', known.users.join() === 'mom,bob', known.users.join());

els['search-input'].value = 'dinner in:ra';
api.applySearchChip('in:random ');
check('a chip replaces only the last word', els['search-input'].value === 'dinner in:random ');
els['search-input'].value = 'dinner fr';
els['search-chips'].children = [];   // the fake does not clear children on innerHTML = ''
api.renderSearchChips();
check('chips are rendered from the input', els['search-chips'].children.length === 1 && els['search-chips'].children[0].dataset.token === 'from:');

const anon = { id: 5, source: 'channel', source_id: 1, source_name: '#general', message: 'Dinner <b>x</b>', username: 'Anonymous',
               display_name: 'Anonymous', created_at: '2026-10-12T09:30:00+00:00', has_link: 1, is_pinned: 1 };
const h = api.searchResultHtml(anon, ['dinner']);
check('the server terms are highlighted and the text is escaped', h.includes('<mark>Dinner</mark>') && h.includes('&lt;b&gt;') && !h.includes('<b>x'));
const ent = api.searchResultHtml({ id: 8, source: 'channel', source_id: 1, source_name: '#general', message: 'fish & chips <amp> lt', display_name: 'Mom' }, ['amp', 'lt', 'chips']);
check('a word that is part of an HTML entity does not cut into the entity',
  ent.includes('fish &amp; <mark>chips</mark> &lt;<mark>amp</mark>&gt; <mark>lt</mark>') && !ent.includes('&<mark>'), ent);
check('the author shown is the display name the server sent', h.includes('>Anonymous<'));
check('flags are shown', h.includes('pinned, link'));
check('the row carries ids in data attributes, not in an inline handler', h.includes('data-id="5"') && !h.includes('onclick'));
const photo = api.searchResultHtml({ id: 6, source: 'channel', source_id: 1, source_name: '#general', message: '', has_image: 1, image_url: '/u/a.png', display_name: 'Mom' }, []);
check('an image-only post shows a label instead of empty text', photo.includes('[image]'));
const file = api.searchResultHtml({ id: 7, source: 'channel', source_id: 1, source_name: '#general', message: '', has_file: 1, attachment_name: 'b.pdf', display_name: 'Mom' }, []);
check('a file-only post names the file', file.includes('[file] b.pdf'));

api.renderSearchResults({ results: [anon], total: 200, capped: true, has_more: true, terms: [], index_complete: false }, false);
check('a capped result says so and still offers more pages while the server has more', els['search-results-note'].textContent.includes('newest 200')
      && els['search-result-count'].textContent === '200+ results' && els['search-results-list'].children.some(c => c.className.includes('search-more-btn')));
check('an unfinished index is announced', els['search-results-note'].textContent.includes('still being added'));
els['search-results-list'].children = [];
api.renderSearchResults({ results: [anon], total: 200, capped: true, has_more: false, terms: [], index_complete: true }, true);
check('the last page of a capped result offers no more pages', !els['search-results-list'].children.some(c => c.className.includes('search-more-btn'))
      && els['search-results-note'].textContent.includes('newest 200'));
els['search-results-list'].children = [];
api.renderSearchResults({ results: [anon], total: 60, capped: false, has_more: true, terms: [], index_complete: true }, false);
check('more pages give a Load more button', els['search-results-list'].children.some(c => c.className.includes('search-more-btn')) && els['search-results-note'].style.display === 'none');

api.navigateToSearchResult('channel', 3, 77);
check('a result click goes through the jump-to-message path', JSON.stringify(jumps[0]) === '["channel",3,77]');

els['search-input'].value = 'from:mom has:image';
els['search-scope'].value = 'channels';
api.executeSearch().then(() => {
  check('the raw query is sent for the server to parse', fetched[0] === '/api/chat/search?q=from%3Amom%20has%3Aimage&scope=channels&offset=0', fetched[0]);
  // Load more: a second click while the request runs does nothing
  let release;
  const gate = new Promise(res => { release = res; });
  const before = fetched.length;
  fetchHook = async () => { await gate; return { ok: true, json: async () => ({ results: [anon], total: 60, has_more: true, terms: [], index_complete: true }) }; };
  const btn = { disabled: false };
  const offsetBefore = api.searchState().offset;
  const first = api.loadMoreSearch(btn);
  const second = api.loadMoreSearch(btn);
  check('Load more disables the button while the page is requested', btn.disabled === true);
  release();
  return Promise.all([first, second]).then(() => {
    check('a second Load more click during the request sends no request', fetched.length - before === 1, fetched.length - before);
    check('the offset moves once for the one page that was fetched', api.searchState().offset === offsetBefore + 1, api.searchState().offset);
    // a failed page leaves the button usable again
    fetchHook = async () => ({ ok: false, json: async () => ({ error: 'boom' }) });
    const retry = { disabled: false };
    return api.loadMoreSearch(retry).then(() => {
      check('a failed Load more enables the button again and shows the error', retry.disabled === false && toasts.includes('boom'));
      return api.loadMoreSearch(retry).then(() => check('and the click can be repeated', fetched.length - before === 3, fetched.length - before));
    });
  });
}).then(() => {
  for (const r of results) console.log('RESULT ' + JSON.stringify(r));
});

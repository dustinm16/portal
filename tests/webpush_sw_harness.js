// Runs static/sw.js against a fake service worker global and prints what it did as JSON.
const fs = require('fs');
const vm = require('vm');
const src = fs.readFileSync(process.argv[2], 'utf8');
const listeners = {};
const shown = [];
const opened = [];
const focused = [];
let clientList = [];
const self = {
    location: { origin: 'https://portal.test' },
    addEventListener: (type, fn) => { listeners[type] = listeners[type] || []; listeners[type].push(fn); },
    registration: { showNotification: (title, options) => { shown.push({ title, options }); return Promise.resolve(); } },
    clients: {
        matchAll: (opts) => Promise.resolve(clientList),
        openWindow: (url) => { opened.push(url); return Promise.resolve(); }
    }
};
class MessageChannel {
    constructor() {
        this.port1 = { onmessage: null };
        this.port2 = { postMessage: (m) => { if (this.port1.onmessage) this.port1.onmessage({ data: m }); } };
    }
}
const sandbox = { self, URL, console, Promise, MessageChannel, setTimeout, clearTimeout };
vm.createContext(sandbox);
vm.runInContext(src, sandbox);

function fire(type, event) {
    let pending = null;
    event.waitUntil = (p) => { pending = p; };
    (listeners[type] || []).forEach(fn => fn(event));
    return pending;
}

(async () => {
    const out = { listeners: Object.keys(listeners).sort(), cases: {} };
    async function push(name, dataFn) {
        shown.length = 0;
        await fire('push', { data: dataFn === null ? null : { json: dataFn } });
        out.cases[name] = shown.slice();
    }
    await push('good', () => ({ type: 'x', title: 'Hello', body: 'World', url: '/chat?c=3', tag: 't1' }));
    await push('malformed', () => { throw new Error('bad json'); });
    await push('nodata', null);
    await push('notobject', () => 'a string');
    await push('absolute', () => ({ title: 'T', url: 'https://evil.example/x' }));
    await push('protorel', () => ({ title: 'T', url: '//evil.example/x' }));
    await push('backslash', () => ({ title: 'T', url: '/\\evil.example' }));
    await push('script', () => ({ title: 'T', url: 'javascript:alert(1)' }));
    await push('dot1', () => ({ title: 'T', url: '/a/..//evil.example' }));
    await push('dot2', () => ({ title: 'T', url: '/.//evil.example' }));
    await push('dot3', () => ({ title: 'T', url: '/a/%2e%2e//evil.example' }));
    await push('encslash', () => ({ title: 'T', url: '/a%2f%2fevil.example' }));
    await push('encback', () => ({ title: 'T', url: '/a%5Cevil.example' }));
    await push('query_ok', () => ({ title: 'T', url: '/chat?c=3&x=..//a#f' }));
    await push('control', () => ({ title: 'A\u0000B', body: 'x\u0007y', url: '/ok' }));

    // a client is a url string, or {url, navigate: 'ok'|'reject', ack: bool, focused, frameType}
    async function click(name, url, clients) {
        opened.length = 0; focused.length = 0;
        const navigated = [], posted = [];
        clientList = clients.map(c => {
            const d = typeof c === 'string' ? { url: c, navigate: 'reject', ack: true } : c;
            const win = {
                url: d.url, focused: !!d.focused, frameType: d.frameType,
                focus: () => { focused.push(d.url); return Promise.resolve(win); },
                navigate: (to) => { if (d.navigate === 'ok') { navigated.push([d.url, to]); return Promise.resolve(win); } return Promise.reject(new TypeError('not controlled')); },
                postMessage: (msg, transfer) => { posted.push([d.url, msg]); if (d.ack && transfer && transfer[0]) transfer[0].postMessage('ok'); }
            };
            return win;
        });
        let closed = false;
        const p = fire('notificationclick', { notification: { close: () => { closed = true; }, data: { url } } });
        await p;
        out.cases[name] = { opened: opened.slice(), focused: focused.slice(), closed, navigated, posted };
    }
    await click('click_open', '/chat?c=3', []);
    await click('click_focus', '/chat?c=3', ['https://portal.test/other', 'https://portal.test/chat?c=3']);
    await click('click_other_origin_tab', '/chat?c=3', ['https://evil.example/chat?c=3']);
    await click('click_tampered', 'https://evil.example/', []);
    await click('click_tampered2', '//evil.example/', []);
    await click('click_dot', '/a/..//evil.example', []);
    await click('click_nodata', undefined, []);
    // an open portal window at another page: it is the one that goes to the target, no new window
    await click('click_navigate', '/chat?c=3', [{ url: 'https://portal.test/about', navigate: 'ok' }]);
    await click('click_relay', '/chat?c=3', [{ url: 'https://portal.test/about', navigate: 'reject', ack: true }]);
    await click('click_front_first', '/chat?c=3', [{ url: 'https://portal.test/a', navigate: 'ok' }, { url: 'https://portal.test/b', navigate: 'ok', focused: true }]);
    // a page that never answers is skipped; with none left a window is opened
    await click('click_no_answer', '/chat?c=3', [{ url: 'https://portal.test/terminal/1', navigate: 'reject', ack: false }]);
    // proxied pages, the embedded browser shell and nested frames are never navigated
    await click('click_proxied', '/chat?c=3', [{ url: 'https://portal.test/proxy/abc/page', navigate: 'ok' }, { url: 'https://portal.test/browser?connection=1', navigate: 'ok' }, { url: 'https://portal.test/x', navigate: 'ok', frameType: 'nested' }]);
    // a tampered target is still the site root, and that is what the open window goes to
    await click('click_tampered_navigate', 'https://evil.example/', [{ url: 'https://portal.test/about', navigate: 'ok' }]);
    console.log(JSON.stringify(out));
})();

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
const sandbox = { self, URL, console, Promise };
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
    await push('control', () => ({ title: 'A\u0000B', body: 'x\u0007y', url: '/ok' }));

    async function click(name, url, clients) {
        opened.length = 0; focused.length = 0;
        clientList = clients.map(u => ({ url: u, focus: () => { focused.push(u); return Promise.resolve(); } }));
        let closed = false;
        const p = fire('notificationclick', { notification: { close: () => { closed = true; }, data: { url } } });
        await p;
        out.cases[name] = { opened: opened.slice(), focused: focused.slice(), closed };
    }
    await click('click_open', '/chat?c=3', []);
    await click('click_focus', '/chat?c=3', ['https://portal.test/other', 'https://portal.test/chat?c=3']);
    await click('click_other_origin_tab', '/chat?c=3', ['https://evil.example/chat?c=3']);
    await click('click_tampered', 'https://evil.example/', []);
    await click('click_tampered2', '//evil.example/', []);
    await click('click_nodata', undefined, []);
    console.log(JSON.stringify(out));
})();

// Runs the address-bar mapping of the embedded browser page (static/browser.html as the server renders it) under
// Node with a stub document: usage `node browser_target_harness.js <rendered page> [secret ...]`.
// The page must not hold any of the secrets; for a page that hides the target the mapping between the address bar
// and the proxy path must work from the name alone.
const fs = require('fs');
let failed = 0;
function check(name, ok, detail) {
    console.log((ok ? 'ok:   ' : 'FAIL: ') + name + (ok || !detail ? '' : '  (' + detail + ')'));
    if (!ok) failed++;
}
const html = fs.readFileSync(process.argv[2], 'utf8');
const secrets = process.argv.slice(3);
const m = html.match(/id="url-input" value="([^"]*)"/);
const inputValue = m[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, '&');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(x => x[1]);
const script = scripts[scripts.length - 1];
const cut = script.indexOf('const urlInput');
const head = script.slice(0, cut);
const mid = script.slice(script.indexOf('const ownBase'), script.indexOf('function getActiveTab'));
global.window = { location: { origin: 'http://portal.test' } };
global.document = { getElementById: () => ({ defaultValue: inputValue }) };
const api = new Function('window', 'document', 'URL',
    head + mid + '; return { targetHidden, targetDisplay, browserMode, proxyBase, proxyPathToDisplay, displayToProxyPath };')(
    global.window, global.document, URL);
const L = api.targetDisplay, B = api.proxyBase;
const hiddenFlag = api.targetHidden;
for (const s of secrets) check('the page does not contain ' + s, !html.includes(s));
if (hiddenFlag) {
    check('the address bar starts with the name', inputValue === L && L.length > 0, inputValue);
    check('the name is the label the script uses', L === inputValue);
    check('the home address shows the name', api.proxyPathToDisplay(B + '/') === L + '/', api.proxyPathToDisplay(B + '/'));
    // in browser mode the connection's own site is reached under /~/ (no origin in the path), else under the base
    const O = api.browserMode ? B + '/~' : B;
    check('typing the name opens the connection root', api.displayToProxyPath(L) === O + '/', api.displayToProxyPath(L));
    check('typing name and path opens that path on the connection', api.displayToProxyPath(L + '/a/b') === O + '/a/b');
    check('typing a bare path opens it on the connection', api.displayToProxyPath('/c') === O + '/c');
    if (!api.browserMode) {
        check('a proxied path shows as name and path', api.proxyPathToDisplay(B + '/a/b') === L + '/a/b');
        check('another origin typed is handled as before (a path under the connection)',
              api.displayToProxyPath('https://other.example/x') === B + '/https://other.example/x');
    } else {
        check('a page of the connection itself shows the name and path', api.proxyPathToDisplay(B + '/~/a/b?x=1') === L + '/a/b?x=1',
              api.proxyPathToDisplay(B + '/~/a/b?x=1'));
        check('the connection root shows the name', api.proxyPathToDisplay(B + '/~/') === L + '/', api.proxyPathToDisplay(B + '/~/'));
        check('a page of another site shows its own address',
              api.proxyPathToDisplay(B + '/https://a.example/x') === 'https://a.example/x');
        check('typing another origin goes to it through the proxy',
              api.displayToProxyPath('https://a.example/z') === B + '/https://a.example/z');
    }
} else {
    check('the owner keeps the address', L.length > 0 && inputValue === L && api.proxyPathToDisplay(B + '/') === L + '/');
    if (!api.browserMode) check('the owner maps the address back', api.displayToProxyPath(L + '/a') === B + '/a');
}
process.exit(failed ? 1 : 0);

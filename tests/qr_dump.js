// Loads static/js/qr.js in a vm context and prints, as JSON, what the tests ask of it.
// usage: node qr_dump.js <qr.js> <json: {"encode": [texts], "rs": [[data, ecLen]], "format": [masks], "version": [versions], "draw": text}>
'use strict';
const fs = require('fs'), vm = require('vm');
const ctx = {}; ctx.window = ctx; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'qr.js' });
const ask = JSON.parse(process.argv[3]), Q = ctx.PortalQR, out = {};
out.encode = (ask.encode || []).map(t => { const q = Q.encode(t); return q ? { version: q.version, size: q.size, mask: q.mask, rows: q.modules.map(r => r.map(b => b ? '1' : '0').join('')) } : null; });
out.rs = (ask.rs || []).map(([d, n]) => Q._internals.remainder(d, n));
out.format = (ask.format || []).map(m => Q._internals.formatBits(m));
out.version = (ask.version || []).map(v => Q._internals.versionBits(v));
if (ask.draw !== undefined) {
  const calls = []; let w = 0, h = 0;
  const canvas = { set width(v) { w = v; }, get width() { return w; }, set height(v) { h = v; }, get height() { return h; },
    getContext: () => ({ set fillStyle(v) { calls.push(['style', v]); }, fillRect: (...a) => calls.push(['rect', ...a]) }) };
  out.draw = { ok: Q.draw(canvas, ask.draw, ask.pixels || 200), width: w, height: h, calls };
}
console.log(JSON.stringify(out));

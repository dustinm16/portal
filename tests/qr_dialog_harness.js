// Runs the "Generate QR code" block of the two-factor setup in static/js/admin.js (cut out between its two comment
// markers) against the real static/js/qr.js and a fake canvas and fake elements: what the dialog shows for an
// address that fits and for one that does not. usage: node qr_dialog_harness.js <qr.js> <admin.js> <uri>
'use strict';
const fs = require('fs'), vm = require('vm');
const ctx = {}; ctx.window = ctx; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx);
const admin = fs.readFileSync(process.argv[3], 'utf8');
const block = admin.slice(admin.indexOf('// Generate QR code'), admin.indexOf('// Reset and show setup modal'));
const els = {
  '2fa-qr-canvas': { style: {}, width: 0, height: 0, getContext: () => ({ fillRect() {}, set fillStyle(v) {} }) },
  '2fa-qr-container': { style: { display: 'none' } },
  '2fa-qr-intro': { textContent: '' },
};
ctx.document = { getElementById: id => els[id] };
ctx.data = { uri: process.argv[4] };
vm.runInContext('(function () { const data = this.data; ' + block + ' }).call(this)', ctx);
console.log(JSON.stringify({ box: els['2fa-qr-container'].style.display, canvasWidth: els['2fa-qr-canvas'].width, intro: els['2fa-qr-intro'].textContent }));

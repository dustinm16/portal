/* A small QR code encoder for the two-factor setup dialog (release 1.24.1). Self-contained: no library, no network.
 *
 * Byte mode, error correction level M, versions 1 to 10 (up to 213 bytes). Longer text is refused (encode returns null,
 * draw returns false) and the dialog then shows only the secret key. The module matrix is built the way ISO/IEC 18004
 * lays it out: finder, timing and alignment patterns, format and version information, the Reed-Solomon coded
 * data interleaved over the blocks of the version, placed in the zigzag order and masked with the best of the eight
 * masks. tests/test_qr.py checks the result with an independent decoder.
 *
 * window.PortalQR.encode(text) -> { version, size, modules (array of rows of booleans, true = dark) } or null
 * window.PortalQR.draw(canvas, text, pixels) -> true when drawn: dark modules on white, a four-module quiet zone,
 * whatever the page theme. Drawing is by canvas calls only (no markup is made from the text).
 */
(function (root) {
    'use strict';

    // Per version 1..10 at level M: [error correction codewords per block, [[blocks, data codewords per block], ...]]
    var BLOCKS = [null,
        [10, [[1, 16]]], [16, [[1, 28]]], [26, [[1, 44]]], [18, [[2, 32]]], [24, [[2, 43]]],
        [16, [[4, 27]]], [18, [[4, 31]]], [22, [[2, 38], [2, 39]]], [22, [[3, 36], [2, 37]]], [26, [[4, 43], [1, 44]]]];
    var ALIGN = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];
    var MAX_VERSION = 10;

    // GF(256) with the polynomial x^8 + x^4 + x^3 + x^2 + 1
    var EXP = [], LOG = [];
    (function () {
        var x = 1, i;
        for (i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 256) x ^= 0x11d; }
        for (i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
    })();
    function gmul(a, b) { return a && b ? EXP[LOG[a] + LOG[b]] : 0; }

    function generator(degree) {      // coefficients, highest power first, leading 1
        var g = [1], i, j;
        for (i = 0; i < degree; i++) {
            var next = [];
            for (j = 0; j <= g.length; j++) next.push(0);
            for (j = 0; j < g.length; j++) { next[j] ^= g[j]; next[j + 1] ^= gmul(g[j], EXP[i]); }
            g = next;
        }
        return g;
    }

    function remainder(data, degree) {
        var g = generator(degree), rem = [], i;
        for (i = 0; i < degree; i++) rem.push(0);
        data.forEach(function (b) {
            var f = b ^ rem.shift();
            rem.push(0);
            for (i = 0; i < degree; i++) rem[i] ^= gmul(g[i + 1], f);
        });
        return rem;
    }

    function utf8(text) {
        var s = unescape(encodeURIComponent(String(text))), out = [], i;
        for (i = 0; i < s.length; i++) out.push(s.charCodeAt(i));
        return out;
    }

    function dataCapacity(version) {
        return BLOCKS[version][1].reduce(function (n, g) { return n + g[0] * g[1]; }, 0);
    }

    function codewordsFor(bytes, version) {
        var bits = [];
        function put(value, length) { for (var i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1); }
        put(4, 4);                                  // byte mode
        put(bytes.length, version <= 9 ? 8 : 16);   // character count
        bytes.forEach(function (b) { put(b, 8); });
        var capBits = dataCapacity(version) * 8;
        put(0, Math.min(4, capBits - bits.length)); // terminator
        while (bits.length % 8) bits.push(0);
        var cw = [], i;
        for (i = 0; i < bits.length; i += 8) {
            var v = 0;
            for (var k = 0; k < 8; k++) v = (v << 1) | bits[i + k];
            cw.push(v);
        }
        for (var pad = 0xec; cw.length < dataCapacity(version); pad ^= 0xec ^ 0x11) cw.push(pad);
        return cw;
    }

    function interleave(cw, version) {
        var spec = BLOCKS[version], ecLen = spec[0], blocks = [], pos = 0;
        spec[1].forEach(function (g) {
            for (var n = 0; n < g[0]; n++) {
                var d = cw.slice(pos, pos + g[1]);
                pos += g[1];
                blocks.push({ data: d, ec: remainder(d, ecLen) });
            }
        });
        var out = [], maxData = Math.max.apply(null, blocks.map(function (b) { return b.data.length; })), i;
        for (i = 0; i < maxData; i++) blocks.forEach(function (b) { if (i < b.data.length) out.push(b.data[i]); });
        for (i = 0; i < ecLen; i++) blocks.forEach(function (b) { out.push(b.ec[i]); });
        return out;
    }

    function newGrid(size, fill) {
        var g = [];
        for (var y = 0; y < size; y++) { var row = []; for (var x = 0; x < size; x++) row.push(fill); g.push(row); }
        return g;
    }

    var MASKS = [
        function (r, c) { return (r + c) % 2 === 0; },
        function (r) { return r % 2 === 0; },
        function (r, c) { return c % 3 === 0; },
        function (r, c) { return (r + c) % 3 === 0; },
        function (r, c) { return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0; },
        function (r, c) { return (r * c) % 2 + (r * c) % 3 === 0; },
        function (r, c) { return ((r * c) % 2 + (r * c) % 3) % 2 === 0; },
        function (r, c) { return ((r + c) % 2 + (r * c) % 3) % 2 === 0; }
    ];

    function penalty(m) {
        var n = m.length, score = 0, x, y, dark = 0, run, i;
        function lines(get) {
            for (var a = 0; a < n; a++) {
                run = 1;
                for (var b = 1; b <= n; b++) {
                    if (b < n && get(a, b) === get(a, b - 1)) run++;
                    else { if (run >= 5) score += 3 + run - 5; run = 1; }
                }
                var s = '';
                for (var k = 0; k < n; k++) s += get(a, k) ? '1' : '0';
                var p;
                for (p = s.indexOf('10111010000'); p >= 0; p = s.indexOf('10111010000', p + 1)) score += 40;
                for (p = s.indexOf('00001011101'); p >= 0; p = s.indexOf('00001011101', p + 1)) score += 40;
            }
        }
        lines(function (a, b) { return m[a][b]; });
        lines(function (a, b) { return m[b][a]; });
        for (y = 0; y < n; y++) for (x = 0; x < n; x++) {
            if (m[y][x]) dark++;
            if (x + 1 < n && y + 1 < n && m[y][x] === m[y][x + 1] && m[y][x] === m[y + 1][x] && m[y][x] === m[y + 1][x + 1]) score += 3;
        }
        var k2 = Math.floor(Math.abs(dark * 100 / (n * n) - 50) / 5);
        for (i = 0; i < k2; i++) score += 10;
        return score;
    }

    function formatBits(mask) {      // level M is 00; BCH(15,5), then the fixed mask
        var data = (0 << 3) | mask, rem = data;
        for (var k = 0; k < 10; k++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
        return ((data << 10) | rem) ^ 0x5412;
    }

    function versionBits(version) {  // BCH(18,6)
        var rem = version;
        for (var i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
        return (version << 12) | rem;
    }

    function build(version, codewords) {
        var size = version * 4 + 17, m = newGrid(size, false), fn = newGrid(size, false);
        function setFn(x, y, dark) { if (x >= 0 && y >= 0 && x < size && y < size) { m[y][x] = !!dark; fn[y][x] = true; } }
        var i, j;
        for (i = 0; i < size; i++) { setFn(6, i, i % 2 === 0); setFn(i, 6, i % 2 === 0); }
        function finder(cx, cy) {
            for (var dy = -4; dy <= 4; dy++) for (var dx = -4; dx <= 4; dx++) {
                var d = Math.max(Math.abs(dx), Math.abs(dy));
                setFn(cx + dx, cy + dy, d !== 2 && d !== 4);
            }
        }
        finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
        var pos = ALIGN[version], last = pos.length - 1;
        for (i = 0; i < pos.length; i++) for (j = 0; j < pos.length; j++) {
            if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
            for (var dy = -2; dy <= 2; dy++) for (var dx = -2; dx <= 2; dx++) setFn(pos[i] + dx, pos[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
        function drawFormat(mask) {
            var bits = formatBits(mask), k;
            function bit(n) { return ((bits >>> n) & 1) !== 0; }
            for (k = 0; k <= 5; k++) setFn(8, k, bit(k));
            setFn(8, 7, bit(6)); setFn(8, 8, bit(7)); setFn(7, 8, bit(8));
            for (k = 9; k < 15; k++) setFn(14 - k, 8, bit(k));
            for (k = 0; k < 8; k++) setFn(size - 1 - k, 8, bit(k));
            for (k = 8; k < 15; k++) setFn(8, size - 15 + k, bit(k));
            setFn(8, size - 8, true);
        }
        drawFormat(0);
        if (version >= 7) {
            var vbits = versionBits(version);
            for (i = 0; i < 18; i++) {
                var bit = ((vbits >>> i) & 1) !== 0, a = size - 11 + (i % 3), b = Math.floor(i / 3);
                setFn(a, b, bit); setFn(b, a, bit);
            }
        }
        // the data, in the zigzag order, two columns at a time from the right, skipping the timing column
        var n = 0, total = codewords.length * 8;
        for (var right = size - 1; right >= 1; right -= 2) {
            if (right === 6) right = 5;
            for (var vert = 0; vert < size; vert++) for (j = 0; j < 2; j++) {
                var x = right - j, upward = ((right + 1) & 2) === 0, y = upward ? size - 1 - vert : vert;
                if (!fn[y][x] && n < total) { m[y][x] = ((codewords[n >>> 3] >>> (7 - (n & 7))) & 1) !== 0; n++; }
            }
        }
        function applyMask(mask) {
            for (var y2 = 0; y2 < size; y2++) for (var x2 = 0; x2 < size; x2++) if (!fn[y2][x2] && MASKS[mask](y2, x2)) m[y2][x2] = !m[y2][x2];
        }
        var best = -1, bestScore = Infinity;
        for (var mask = 0; mask < 8; mask++) {
            applyMask(mask); drawFormat(mask);
            var sc = penalty(m);
            if (sc < bestScore) { bestScore = sc; best = mask; }
            applyMask(mask);
        }
        applyMask(best); drawFormat(best);
        return { version: version, size: size, mask: best, modules: m };
    }

    function encode(text) {
        var bytes = utf8(text), version;
        for (version = 1; version <= MAX_VERSION; version++) {
            var lenBits = version <= 9 ? 8 : 16;
            if (4 + lenBits + bytes.length * 8 <= dataCapacity(version) * 8 && (lenBits === 16 || bytes.length < 256)) {
                return build(version, interleave(codewordsFor(bytes, version), version));
            }
        }
        return null;
    }

    function draw(canvas, text, pixels) {
        var qr = encode(text);
        if (!qr || !canvas || !canvas.getContext) return false;
        var quiet = 4, cells = qr.size + 2 * quiet, scale = Math.max(1, Math.floor((pixels || 200) / cells));
        canvas.width = canvas.height = cells * scale;
        var ctx = canvas.getContext('2d');
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#000000';
        for (var y = 0; y < qr.size; y++) for (var x = 0; x < qr.size; x++) {
            if (qr.modules[y][x]) ctx.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale);
        }
        return true;
    }

    root.PortalQR = { encode: encode, draw: draw, MAX_VERSION: MAX_VERSION,
        _internals: { remainder: remainder, formatBits: formatBits, versionBits: versionBits, dataCapacity: dataCapacity } };
})(typeof window !== 'undefined' ? window : this);

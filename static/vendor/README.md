# Vendored libraries

Each folder here holds one library, copied unchanged from its npm package, with its own `README.md` (version, source, sha256 of every file) and `LICENSE`. `tests/test_vendor_libs.py` checks the files against those hashes, so never change a byte of a vendored file.

Source maps are not shipped. Six scripts end with a `sourceMappingURL` comment that names a `.map` file the portal does not serve, so a browser with its developer tools open asks for it and logs a 404; the page itself is not affected:

- `chart.js/chart.umd.js`
- `dompurify/purify.min.js`
- `hls.js/hls.min.js`
- `marked/marked.umd.js`
- `xterm-addon-fit/xterm-addon-fit.js`
- `xterm/xterm.js`

`highlight.js/highlight.min.js` and the noVNC files name no map. The comment is left in place on purpose: removing it would change the file and its checksum.

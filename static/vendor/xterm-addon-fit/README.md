# xterm-addon-fit 0.8.0 (vendored)

Used by `terminal.html` (fits the terminal to its window; the terminal itself is the xterm copy in `../xterm/`), so those pages load no script or style from another host.

Source: the npm package `xterm-addon-fit@0.8.0`, tarball `https://registry.npmjs.org/xterm-addon-fit/-/xterm-addon-fit-0.8.0.tgz`
(sha512 `yj3Np7XlvxxhYF/EJ7p3KHaMt6OdwQ+HDu573Vx1lRXsVxOcnVJs51RgjZOouIZOczTsskaS+CpXspK81/DLqw==`,
equal to the registry's `dist.integrity`). Fetched once on 2026-11-24. The files are copied unchanged:

| File | In the package | sha256 |
|------|----------------|--------|
| `xterm-addon-fit.js` | `lib/xterm-addon-fit.js` (already minified; the package has no `.min.js`) | `10f3194c5f17c1786fb7d5db865c1ec8539b6736a318063fd38bdaaf7c46848f` |
| `LICENSE` | `LICENSE` (licence) | `e256f01188af527e4d06d21d06fbf785ae9c50d4b328bf03cbe0ba7f0aa4228f` |

Licence: MIT (package.json says `MIT`; see `LICENSE`). Project: https://github.com/xtermjs/xterm.js

The source map is not included; the last line of the script names it, which only matters to browser developer tools.

`tests/test_vendor_libs.py` checks these hashes. To update: fetch the new tarball, compare it with the registry's integrity value,
replace the files, and change the version and hashes here and in the test, the README Third-Party Components table and the `?v=` of the pages that load it.

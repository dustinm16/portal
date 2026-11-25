# dompurify 3.5.0 (vendored)

Used by `github.html` (sanitises the rendered README), so those pages load no script or style from another host.

The page asked for `dompurify@3`, a floating major version. This is the newest 3.x on 2026-11-24 (3.5.0). The bytes were not compared with what the CDN served.

Source: the npm package `dompurify@3.5.0`, tarball `https://registry.npmjs.org/dompurify/-/dompurify-3.5.0.tgz`
(sha512 `LYC0ZkE8P1V42JsRYTwMdme/2ET8SpOc5AA2eOFjP/IadvRd2fwiT4TVz5vkfy0XUx12aS2UaRkTnfVPNOv9vw==`,
equal to the registry's `dist.integrity`). Fetched once on 2026-11-24. The files are copied unchanged:

| File | In the package | sha256 |
|------|----------------|--------|
| `purify.min.js` | `dist/purify.min.js` (minified build, sets the global `DOMPurify`) | `f69a46022ab1f53e969c8ebbca98172c8995785a9b3be72ea4a12d25b1a1bf67` |
| `LICENSE` | `LICENSE` (licence) | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |
| `LICENSE-MPL` | `LICENSE-MPL` (licence) | `fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85` |

Licence: (MPL-2.0 OR Apache-2.0) (package.json says `(MPL-2.0 OR Apache-2.0)`; see `LICENSE`, `LICENSE-MPL`). Project: https://github.com/cure53/DOMPurify

The source map is not included; the last line of the script names it, which only matters to browser developer tools.

`tests/test_vendor_libs.py` checks these hashes. To update: fetch the new tarball, compare it with the registry's integrity value,
replace the files, and change the version and hashes here and in the test, the README Third-Party Components table and the `?v=` of the pages that load it.

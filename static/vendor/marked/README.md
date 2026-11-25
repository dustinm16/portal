# marked 18.3.0 (vendored)

Used by `github.html` (README rendering), so those pages load no script or style from another host.

The page asked for `marked/marked.min.js` with no version, which resolves to the newest release. On 2026-11-24 that is 18.3.0, whose package has no `marked.min.js` at its top level (it ships `lib/marked.umd.js`), so the old URL most likely returned nothing. The UMD build is the file that replaces it.

Source: the npm package `marked@18.3.0`, tarball `https://registry.npmjs.org/marked/-/marked-18.3.0.tgz`
(sha512 `ed8zmPXlBb3UfGXN5iHMQyMhFpdqLgoV5umUXx/Q1R+FW3q8VpqpyoKUwlENL9appo2UMvNLURDVaT3AMOryGA==`,
equal to the registry's `dist.integrity`). Fetched once on 2026-11-24. The files are copied unchanged:

| File | In the package | sha256 |
|------|----------------|--------|
| `marked.umd.js` | `lib/marked.umd.js` (UMD build, sets the global `marked`) | `f8c7f128939415995e2219e8a84bec42fab27f5980d22e361339e6901da5eadf` |
| `LICENSE` | `LICENSE` (licence) | `8e3a3f82f59a60958f56ca08f445647c32a4733dc7ca6c2c46f6eb898471ab9c` |

Licence: MIT (package.json says `MIT`; see `LICENSE`). Project: https://github.com/markedjs/marked

The source map is not included; the last line of the script names it, which only matters to browser developer tools.

`tests/test_vendor_libs.py` checks these hashes. To update: fetch the new tarball, compare it with the registry's integrity value,
replace the files, and change the version and hashes here and in the test, the README Third-Party Components table and the `?v=` of the pages that load it.

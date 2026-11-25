# @highlightjs/cdn-assets 11.12.0 (vendored)

Used by `chat.html` (code blocks in messages), so those pages load no script or style from another host.

The page asked for `gh/highlightjs/cdn-release@11`, a floating major version. This copy is the npm twin of that repository, the package `@highlightjs/cdn-assets`, at its newest 11.x on 2026-11-24 (11.12.0). The bytes were not compared with what the CDN served.

Source: the npm package `@highlightjs/cdn-assets@11.12.0`, tarball `https://registry.npmjs.org/@highlightjs/cdn-assets/-/cdn-assets-11.12.0.tgz`
(sha512 `KvOKXODaiFmId9xaq3xc5xCL66wVLUuOngDbO9B/kewbFTqdGbn2nJxNhN3H5R1cgDTVj6R8vH0zgiNDEGjpDw==`,
equal to the registry's `dist.integrity`). Fetched once on 2026-11-24. The files are copied unchanged:

| File | In the package | sha256 |
|------|----------------|--------|
| `highlight.min.js` | `highlight.min.js` (common-languages build) | `8ab71eb09c51f501e5e25157d9cff100e46cc29bcbfc744d0b746d451fca7f53` |
| `github-dark.min.css` | `styles/github-dark.min.css` (theme used by the chat page) | `9f208d022102b1d0c7aebfecd8e42ca7997d5de636649d2b31ea63093d809019` |
| `LICENSE` | `LICENSE` (licence) | `6c081431591d9df696c82dc598fe1423765b8a299b200ed00b281afd0f64c490` |

Licence: BSD-3-Clause (package.json says `BSD-3-Clause`; see `LICENSE`). Project: https://github.com/highlightjs/highlight.js

The source map is not included. `highlight.min.js` ends without a `sourceMappingURL` comment, so nothing asks for a map and browser developer tools show no 404 for this file.

`tests/test_vendor_libs.py` checks these hashes. To update: fetch the new tarball, compare it with the registry's integrity value,
replace the files, and change the version and hashes here and in the test, the README Third-Party Components table and the `?v=` of the pages that load it.

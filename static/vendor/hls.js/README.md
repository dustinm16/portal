# hls.js 1.5.17 (vendored)

Used by `live.html`, `watch.html`, `streams.html`, `vod-player.html` (HLS playback), so those pages load no script or style from another host.

Source: the npm package `hls.js@1.5.17`, tarball `https://registry.npmjs.org/hls.js/-/hls.js-1.5.17.tgz`
(sha512 `wA66nnYFvQa1o4DO/BFgLNRKnBTVXpNeldGRBJ2Y0SvFtdwvFKCbqa9zhHoZLoxHhZ+jYsj3aIBkWQQCPNOhMw==`,
equal to the registry's `dist.integrity`). Fetched once on 2026-11-24. The files are copied unchanged:

| File | In the package | sha256 |
|------|----------------|--------|
| `hls.min.js` | `dist/hls.min.js` (minified build; the package's `main` is `dist/hls.js`, the bare jsDelivr URL served this minified build) | `484054e8cd03d3f6d1781fb7f402bdc318d8a4c527f933a95c624e27cc9a9470` |
| `LICENSE` | `LICENSE` (licence) | `ca8773cf798c7ed997d4dd7c8e23c348699f8d5b7462636694cc14de6cda12db` |

Licence: Apache-2.0 (package.json says `Apache-2.0`; see `LICENSE`). Project: https://github.com/video-dev/hls.js

The source map is not included; the last line of the script names it, which only matters to browser developer tools.

`tests/test_vendor_libs.py` checks these hashes. To update: fetch the new tarball, compare it with the registry's integrity value,
replace the files, and change the version and hashes here and in the test, the README Third-Party Components table and the `?v=` of the pages that load it.

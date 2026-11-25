# chart.js 4.4.7 (vendored)

Used by `admin.html` (charts of the admin page), so those pages load no script or style from another host.

Source: the npm package `chart.js@4.4.7`, tarball `https://registry.npmjs.org/chart.js/-/chart.js-4.4.7.tgz`
(sha512 `pwkcKfdzTMAU/+jNosKhNL2bHtJc/sSmYgVbuGTEDhzkrhmyihmP7vUc/5ZK9WopidMDHNe3Wm7jOd/WhuHWuw==`,
equal to the registry's `dist.integrity`). Fetched once on 2026-11-24. The files are copied unchanged:

| File | In the package | sha256 |
|------|----------------|--------|
| `chart.umd.js` | `dist/chart.umd.js` (already minified (the package has no `.min.js`; jsDelivr generated its own minified copy for the old URL)) | `2812cb8825fdc57469eb2f7bb055e9429244e599920511ee477e828499b632cb` |
| `LICENSE.md` | `LICENSE.md` (licence) | `41a84aa2caba645f966a18d9c2056b73e6d3a81d80bc0046bc0011a2634d4cce` |

Licence: MIT (package.json says `MIT`; see `LICENSE.md`). Project: https://github.com/chartjs/Chart.js

The source map is not included; the last line of the script names it, which only matters to browser developer tools.

`tests/test_vendor_libs.py` checks these hashes. To update: fetch the new tarball, compare it with the registry's integrity value,
replace the files, and change the version and hashes here and in the test, the README Third-Party Components table and the `?v=` of the pages that load it.

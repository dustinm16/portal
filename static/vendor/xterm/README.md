# xterm.js 5.3.0 (vendored)

Used by the Recordings player of the admin page (`static/js/recordings-admin.js`) so that
page loads no terminal code from another host. `terminal.html` still loads its own copy
from a CDN; that is a separate matter.

Source: the npm package `xterm@5.3.0`, tarball `https://registry.npmjs.org/xterm/-/xterm-5.3.0.tgz`
(sha512 `8QqjlekLUFTrU6x7xck1MsPzPA571K5zNqWm0M0oroYEWVOptZ0+ubQSkQ3uxIEhcIHRujJy6emDWX4A7qyFzg==`,
equal to the registry's `dist.integrity`). The files are copied unchanged:

| File | In the package | sha256 |
|------|----------------|--------|
| `xterm.js` | `lib/xterm.js` (already minified; the package has no `lib/xterm.min.js`) | `f0aea0f75f48559013ae6643c2479dd737d26da42d5524e6d2b70915ae6523c7` |
| `xterm.css` | `css/xterm.css` | `832f3f2c603b43ad4351ff04970150cc7a873014276db126a6065c6dd81e4872` |
| `LICENSE` | `LICENSE` | `b569f629d00f2626a8100df2a1798210535621e42164dfd426a6fe5aac7b0ccd` |

Licence: MIT (see `LICENSE`). The source map is not included; the last line of `xterm.js`
names it, which only matters to browser developer tools.

`tests/test_recording_ui.py` checks these hashes. To update: fetch the new tarball, compare it
with the registry's integrity value, replace the files, and change the versions and hashes here
and in the test, the README Third-Party Components table and the `?v=` of the two URLs in
`recordings-admin.js`.

# noVNC 1.4.0 (vendored)

Used by `vnc.html`, which imports `core/rfb.js` as an ES module, so that page loads no script from another host.

Source: the npm package `@novnc/novnc@1.4.0`, tarball `https://registry.npmjs.org/@novnc/novnc/-/novnc-1.4.0.tgz`
(sha512 `kW6ALMc5BuH08e/ond/I1naYcfjc19JYMN1EdtmgjjjzPGCjW8fMtVM3MwM6q7YLRjPlQ3orEvoKMgSS7RkEVQ==`,
equal to the registry's `dist.integrity`). Fetched once on 2026-11-24. The files are copied unchanged, with the
package's own directory layout (`core/` and `vendor/pako/`), because the modules import each other by relative path.
Only the 45 modules that `core/rfb.js` imports, directly or through other modules, are included (found by following the
`import ... from` lines), plus the licence files. Not included: the package's `lib/` (the CommonJS copy), `docs/`,
`app/` and the pako modules nothing imports.

The modules are loaded as `/static/vendor/novnc/core/rfb.js?v=1.4.0`. The modules it imports are requested
without a `?v=` (a module cannot carry one for its own imports), so after an upgrade Cloudflare may serve an old
module for up to 4 hours; upgrade by changing the version in the `vnc.html` import and expect that delay.

Licence: MPL-2.0 for noVNC (`LICENSE.txt`, `AUTHORS`), MIT for the bundled pako (`vendor/pako/LICENSE`). The files are
unmodified, so the MPL's requirement to make the source available is met by this directory and the source URL above.

| File | sha256 |
|------|--------|
| `core/base64.js` | `76d6b7ec73aed8cbc72b49b8b865bcb334acc59a6b0e96b19bc39c9e8e053ae3` |
| `core/decoders/copyrect.js` | `5d63ee70a1746f60f4ec890768cd661353412cde9ce2af5f85e28615f6f4fd68` |
| `core/decoders/hextile.js` | `adcf5587d6b118016d1d05856dd7998b040dd5096cc8454f46f76beea0960945` |
| `core/decoders/jpeg.js` | `86711fbe888a7f4108b97efcd35c0f096bdbceeea1c60a3ce20d128dc39b7b5e` |
| `core/decoders/raw.js` | `03945407d82505b3cf0d22636e3fd52bf1036cfcf64f4f5459d65dd771763a64` |
| `core/decoders/rre.js` | `e9574abfd159dce1ea4f1b1b2e8bdf83d3ff5f0b66bb4e8176a7b54fec4aa36f` |
| `core/decoders/tight.js` | `9a670fe9d84b48b695d6941e667eaf8e2728da8025d0848edc920f91b39f2d5e` |
| `core/decoders/tightpng.js` | `a6b340dfbc4f78126093dba599c696c163e5c6419f7b0d7b90cedfd3ca37b031` |
| `core/decoders/zrle.js` | `b8d6589c3381799965979384ec4c2ec4fb3ee63aaa934d7033e1b8623a51abfe` |
| `core/deflator.js` | `be6d39a9eb7cde51fd265037e19a735c3d429e846cb0085b982775e0fdf4ff6b` |
| `core/des.js` | `13788bf11d4bd168cfd15582c493e4e10add7475c8b4bf071df6b7c783574060` |
| `core/display.js` | `1ac2bde56f40e98f096ebdcaafc7a89ca19662a84db91027c58edf278b159915` |
| `core/encodings.js` | `2f6758a41cc76568b51833a609e1fe2382250a3068d87bf5ec4db6825c688576` |
| `core/inflator.js` | `ee782c387f5d0c910631f07dda19599c8cd2ccedf7d169e640ed536d3d85e8bd` |
| `core/input/domkeytable.js` | `b25578a71e7822d1337f8da383d5f2f29b79fef13e6b0a4d33fd3c518faf9d30` |
| `core/input/fixedkeys.js` | `59af0fce68461b14f7ac62643d087655287e61c158aefa55c8a1ef0c9e1c01f9` |
| `core/input/gesturehandler.js` | `1f5399d6b2db43d7ce7bf7a70d868597f79aeff4c4735f1d5472738e4dea78d7` |
| `core/input/keyboard.js` | `f9c77fa3f5400b89cdb64e7e235bd76431a9f3199d8982e36977c9882976c5c5` |
| `core/input/keysym.js` | `4ddf0e21f07328358974d91aa2d7f839ba2116688b28e43d3f6f4e2eae8c45cf` |
| `core/input/keysymdef.js` | `76f338d45fb73b7decb7d8b4ef6e95edf7ce9583722c5220642a9be85fc2cc89` |
| `core/input/util.js` | `43bfb6f255a7030c6ca38749c3ee1a5feeb601e296ff32f6a1d0bd483edfa852` |
| `core/input/vkeys.js` | `acea26edd998a1f4c194d0d84cf5ba4bf74046ca082890ec6b288eb70c1d8156` |
| `core/input/xtscancodes.js` | `f0fc982627e1c02feaac1bd50d7fdd3bcbb05f0062b910d8002f47d1b08967a6` |
| `core/ra2.js` | `ca130951083bf735f2a432dd1833244cfaeeee3c19e2b8733cf797c69c66b5a2` |
| `core/rfb.js` | `f497c8b080f76aee1667a3c41db61be178f93e9ce4c39d150b8bcdbefdc2b0ca` |
| `core/util/browser.js` | `2e802163699470b80a863314c46bc557838d5944c21f0ca96e5a81ec9bc86492` |
| `core/util/cursor.js` | `b29fa2da483012632a64ee7a41a151bcffda6bfa3fd79c158ae4a764a545e612` |
| `core/util/element.js` | `9684e296e52a5ff3dc46b9a2ef5a247ae63befb20691ffb57fd1f4a8b1a12c55` |
| `core/util/events.js` | `026290a0324d14b906f0d943085b327fc8c1ccd2f49a289ce7bd5a56e971bb03` |
| `core/util/eventtarget.js` | `f26f0c32559d96d5a147bbdee6f6944d2b38db85dfac58738e58061c1472075c` |
| `core/util/int.js` | `9841c341f4568413a01c1ba447ee65d0463f1a3a8d77d6cffe4142970af9102a` |
| `core/util/logging.js` | `505e011b6b2420d40090d123866484bbf7a881c93fcdaca9a0e17b703550375c` |
| `core/util/md5.js` | `67864db2b4f8849beff8ac646757bdcc4b5ccff5fe0829d1703f0ec017a99aff` |
| `core/util/strings.js` | `9d8e8b48613e92dd9ee69ef1bdc897dba056e710ce4026578d7b59fcf8a544e9` |
| `core/websock.js` | `2ed1d247ae9b109fc681dcdaef650b37e6bf9d30880ef6183f0d9607bbc7c286` |
| `vendor/pako/lib/utils/common.js` | `0749bc4661ed186714b90e7f2321c9625a8ce7c680563bfe3ac6df7aa332bf28` |
| `vendor/pako/lib/zlib/adler32.js` | `7412dd3ecc015888b99292f45e4d4ba69abc77f208508c9a1c93e8dfe54ba6cd` |
| `vendor/pako/lib/zlib/crc32.js` | `897fa9eabd2bb239ec632326dbff85bc72cc81d4da80265cde59520db339f405` |
| `vendor/pako/lib/zlib/deflate.js` | `d2a498ad04bb5d1f67ba01696c31a2e88e8b88e4fc6c36c635294d1c445b22c1` |
| `vendor/pako/lib/zlib/inffast.js` | `ec1e0f7abeec681a0d5e3da46d06f499969cbf265eaaa5e21a135d2a9b878c16` |
| `vendor/pako/lib/zlib/inflate.js` | `321582ddc4023e47aa981a71caed0e1dad8b58f0d9e93a0b0a34fe7e3c45e05f` |
| `vendor/pako/lib/zlib/inftrees.js` | `94780cbdef562bcd0434c7e6f4faca1ff6be6980bf7305a200809d98d419d9c7` |
| `vendor/pako/lib/zlib/messages.js` | `7860a8d3c873c28e4f5f92db9ca3e45006e21b084210d87b8b7775cddccf05ed` |
| `vendor/pako/lib/zlib/trees.js` | `ad9cb5245b9e39edd164234d6ca19febb9dba683f1f99a67af48d62931d91426` |
| `vendor/pako/lib/zlib/zstream.js` | `240917347c379b1ad33b8bf07cc6981557173bc3408f35e9875866a14b9967b2` |
| `LICENSE.txt` | `e522f81d37206b944461b6b50bc79bd61ccc838b442ba51871f9566de531f5c4` |
| `AUTHORS` | `16ee0ef356d5107a4bc039f91abc99a341dc62b9aa8dd47547a2baed38507509` |
| `vendor/pako/LICENSE` | `3bc404ffa7888053253eedcc5a667619aa08dc1be0bea400e5ff28c51602180f` |

`tests/test_vendor_libs.py` checks these hashes. To update: fetch the new tarball, compare it with the registry's
integrity value, redo the import closure, replace the files and change the version and hashes here and in the test,
the README Third-Party Components table and the import line in `vnc.html`.

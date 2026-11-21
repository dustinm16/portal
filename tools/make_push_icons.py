"""Draw the app icons the web manifest names (static/icons/*.png) with Pillow.

Plain shapes only: a rounded square with a ring and a dot, no name or text. The output is
committed, so this runs when the design changes, not at start-up:

    venv/bin/python tools/make_push_icons.py
"""

import sys
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "static" / "icons"
BG = (15, 23, 42, 255)        # #0f172a, the manifest's theme colour
FG = (56, 189, 248, 255)      # sky blue


def draw(size: int, maskable: bool = False) -> Image.Image:
    scale = 4                                       # draw large, shrink for smooth edges
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if maskable:
        d.rectangle((0, 0, s, s), fill=BG)          # the platform crops it, so fill the square
        inner = 0.62                                # keep the glyph inside the safe zone
    else:
        d.rounded_rectangle((0, 0, s - 1, s - 1), radius=s // 5, fill=BG)
        inner = 0.74
    c = s / 2
    r = s * inner / 2
    w = max(2, int(s * 0.06))
    d.ellipse((c - r, c - r, c + r, c + r), outline=FG, width=w)
    r2 = r * 0.55
    d.ellipse((c - r2, c - r2, c + r2, c + r2), outline=FG, width=w)
    r3 = r * 0.2
    d.ellipse((c - r3, c - r3, c + r3, c + r3), fill=FG)
    return img.resize((size, size), Image.LANCZOS)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    draw(192).save(OUT / "icon-192.png", optimize=True)
    draw(512).save(OUT / "icon-512.png", optimize=True)
    draw(512, maskable=True).save(OUT / "icon-maskable-512.png", optimize=True)
    draw(96).save(OUT / "badge-96.png", optimize=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
